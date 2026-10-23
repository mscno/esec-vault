package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/mscno/esec-vault/internal/kms"
	"github.com/mscno/esec-vault/internal/storage"
	"github.com/mscno/esec-vault/internal/team"
)

// GroupWorkloadCmd adds a workload: an app with no secret of its own.
type GroupWorkloadCmd struct {
	oidcFlags

	Group string `arg:"" help:"Group, such as acme/production"`
	Name  string `arg:"" help:"Workload name, such as store"`

	GCPKey            string `name:"gcp-key" help:"Cloud KMS key version that wraps the group key: projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/N"`
	GCPProvider       string `name:"gcp-provider" help:"Workload identity provider that trusts the workload's OIDC tokens: projects/NUMBER/locations/global/workloadIdentityPools/POOL/providers/PROVIDER"`
	GCPServiceAccount string `name:"gcp-service-account" help:"A service account the workload acts as, when the key's IAM grants that rather than the pool"`

	OpenBaoKey      string `name:"openbao-key" help:"Self-hosted OpenBao Transit key version instead: https://HOST/MOUNT/KEY/VERSION, such as https://bao.example.com/transit/esec-store/1"`
	OpenBaoRole     string `name:"openbao-role" help:"OpenBao JWT auth mount and role the workload logs in with, such as jwt/fly-store"`
	OpenBaoAudience string `name:"openbao-audience" default:"esec-openbao" help:"The audience the OpenBao role binds"`

	PublicKey string `name:"public-key" type:"existingfile" help:"The KMS key's public key (PEM); default: ask gcloud, or OpenBao with BAO_TOKEN"`
	Out       string `help:"Write the workload's descriptor to this file too"`
}

// Run implements group workload.
func (c *GroupWorkloadCmd) Run(ctx *cliCtx) error {
	policy, err := c.policy()
	if err != nil {
		return err
	}
	if policy == nil {
		return errors.New("say where the workload runs: --fly-org ORG --fly-app APP (or --github-repo OWNER/NAME); it has no secret, so that is what proves it")
	}
	key, err := c.kmsKey()
	if err != nil {
		return err
	}
	pemText, err := c.publicKey(key)
	if err != nil {
		return err
	}
	if key.PublicKey, err = kms.PublicKeyFromPEM(pemText); err != nil {
		return err
	}
	if err := key.Validate(); err != nil {
		return err
	}
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	id, err := groupID(a, c.Group)
	if err != nil {
		return err
	}
	bg, cancel := timeout(2 * time.Minute)
	defer cancel()
	ref, err := a.AddWorkload(bg, id, c.Name, key, policy)
	if err != nil {
		return err
	}
	desc := ref.String()
	fmt.Printf("✓ Workload %s (%s) of %s: it reads whatever the group reads, from %s.\n", c.Name, ref.ID, id, policy.Describe())
	fmt.Printf("  Its group key is wrapped with %s; only that KMS can unwrap it, for that workload.\n", key.Name)
	fmt.Println("\nIts descriptor is not a secret: put it in the app's plain configuration, such as fly.toml:")
	fmt.Printf("\n  [env]\n    ESEC_VAULT_WORKLOAD = %q\n\n", desc)
	fmt.Println("and start the app with: esec-vault machine run -- ./your-command")
	if c.Out != "" {
		if err := storage.Write(c.Out, []byte(desc+"\n")); err != nil {
			return err
		}
		fmt.Printf("Wrote it to %s.\n", c.Out)
	}
	return nil
}

// kmsKey names the KMS key from the flags: Google Cloud KMS or OpenBao.
func (c *GroupWorkloadCmd) kmsKey() (kms.Key, error) {
	switch {
	case c.OpenBaoKey != "" && c.GCPKey != "":
		return kms.Key{}, errors.New("use one KMS: --gcp-key or --openbao-key")
	case c.OpenBaoKey != "":
		if c.OpenBaoRole == "" {
			return kms.Key{}, errors.New("--openbao-key needs --openbao-role (esec vault kms setup openbao prints both)")
		}
		return kms.Key{Provider: "openbao", Name: c.OpenBaoKey, Audience: c.OpenBaoAudience, Principal: c.OpenBaoRole}, nil
	case c.GCPKey != "" && c.GCPProvider != "":
		return kms.Key{Provider: "gcp", Name: c.GCPKey, Audience: c.GCPProvider, Principal: c.GCPServiceAccount}, nil
	}
	return kms.Key{}, errors.New("name the KMS key: --gcp-key and --gcp-provider (esec vault kms setup gcp prints them), or --openbao-key and --openbao-role")
}

// publicKey reads the key's public half from --public-key, or from the KMS.
func (c *GroupWorkloadCmd) publicKey(key kms.Key) ([]byte, error) {
	if c.PublicKey != "" {
		return os.ReadFile(c.PublicKey)
	}
	return kms.FetchPublicKey(context.Background(), key)
}

// GroupRekeyWorkloadsCmd moves workloads to another KMS key.
type GroupRekeyWorkloadsCmd struct {
	Group    string   `arg:"" help:"Group, such as acme/production"`
	Workload []string `sep:"," help:"Only these workloads (default: all of the group's)"`

	GCPKey            string `name:"gcp-key" help:"The new Cloud KMS key version"`
	GCPProvider       string `name:"gcp-provider" help:"Workload identity provider for it"`
	GCPServiceAccount string `name:"gcp-service-account" help:"A service account the workloads act as"`
	OpenBaoKey        string `name:"openbao-key" help:"Or the new OpenBao Transit key version: https://HOST/MOUNT/KEY/VERSION"`
	OpenBaoRole       string `name:"openbao-role" help:"OpenBao JWT auth mount and role, such as jwt/fly-store"`
	OpenBaoAudience   string `name:"openbao-audience" default:"esec-openbao" help:"The audience the OpenBao role binds"`
	PublicKey         string `name:"public-key" type:"existingfile" help:"The new key's public key (PEM); default: ask gcloud, or OpenBao with BAO_TOKEN"`
}

// Run implements group rekey-workloads.
func (c *GroupRekeyWorkloadsCmd) Run(ctx *cliCtx) error {
	w := GroupWorkloadCmd{GCPKey: c.GCPKey, GCPProvider: c.GCPProvider, GCPServiceAccount: c.GCPServiceAccount, OpenBaoKey: c.OpenBaoKey, OpenBaoRole: c.OpenBaoRole, OpenBaoAudience: c.OpenBaoAudience, PublicKey: c.PublicKey}
	key, err := w.kmsKey()
	if err != nil {
		return err
	}
	pemText, err := w.publicKey(key)
	if err != nil {
		return err
	}
	if key.PublicKey, err = kms.PublicKeyFromPEM(pemText); err != nil {
		return err
	}
	a, err := openAccount(ctx)
	if err != nil {
		return err
	}
	id, err := groupID(a, c.Group)
	if err != nil {
		return err
	}
	bg, cancel := timeout(2 * time.Minute)
	defer cancel()
	moved, err := a.RekeyWorkloads(bg, id, c.Workload, key)
	if err != nil {
		return err
	}
	if len(moved) == 0 {
		fmt.Printf("No workload of %s needed moving.\n", id)
		return nil
	}
	fmt.Printf("✓ %s now unwrap with %s; their descriptors stay. Retire the old key once they have restarted.\n", strings.Join(moved, ", "), key.Name)
	return nil
}

// KMSCmd sets up external KMS keys for workloads.
type KMSCmd struct {
	Setup KMSSetupCmd `cmd:"" help:"Set up a KMS key and identity federation for workloads with no secret."`
}

// KMSSetupCmd sets up a provider.
type KMSSetupCmd struct {
	GCP     KMSSetupGCPCmd     `cmd:"" name:"gcp" help:"Google Cloud: a Cloud KMS key, and workload identity federation trusting Fly.io's OIDC tokens."`
	OpenBao KMSSetupOpenBaoCmd `cmd:"" name:"openbao" help:"Self-hosted OpenBao: a Transit key per app, and JWT login trusting Fly.io's OIDC tokens."`
}

// KMSSetupOpenBaoCmd prints the OpenBao setup for workloads on Fly.io: a
// Transit RSA key, a decrypt-only policy and a JWT role per app, so each
// app can unwrap only its own group key.
type KMSSetupOpenBaoCmd struct {
	Addr     string   `required:"" help:"OpenBao address, such as https://bao.example.com"`
	FlyOrg   string   `name:"fly-org" required:"" help:"Fly.io organisation slug (fly orgs list)"`
	FlyApp   []string `name:"fly-app" sep:"," required:"" help:"Fly.io apps; each gets its own key"`
	Audience string   `default:"esec-openbao" help:"Audience the roles bind; workloads ask Fly.io for tokens with it"`
}

// Run implements kms setup openbao.
func (c *KMSSetupOpenBaoCmd) Run(_ *cliCtx) error {
	name := regexp.MustCompile(`^[a-z0-9-]{1,63}$`)
	for _, v := range append([]string{c.FlyOrg, c.Audience}, c.FlyApp...) {
		if !name.MatchString(v) {
			return fmt.Errorf("%q: use lowercase letters, digits and dashes", v)
		}
	}
	addr := strings.TrimRight(c.Addr, "/")
	issuer := team.FlyIssuerBase + "/" + c.FlyOrg
	fmt.Printf("# One-time OpenBao setup (bao CLI, signed in as an admin, BAO_ADDR=%s).\n", addr)
	fmt.Println("# Run OpenBao apart from the vault server, so breaking one is not enough.")
	fmt.Println("bao secrets enable transit")
	fmt.Println("bao auth enable jwt")
	fmt.Printf("bao write auth/jwt/config oidc_discovery_url=%s bound_issuer=%s\n", issuer, issuer)
	for _, app := range c.FlyApp {
		key := "esec-" + app
		fmt.Printf("\n# %s: its own key, a policy that may only decrypt with it, and a role for its Machines.\n", app)
		fmt.Printf("bao write -f transit/keys/%s type=rsa-3072\n", key)
		fmt.Printf("echo 'path \"transit/decrypt/%s\" { capabilities = [\"update\"] }' | bao policy write %s -\n", key, key)
		fmt.Printf("bao write auth/jwt/role/fly-%s - <<'EOF'\n", app)
		fmt.Printf(`{"role_type": "jwt", "user_claim": "sub", "bound_audiences": ["%s"], "bound_claims": {"org_name": "%s", "app_name": "%s"}, "token_policies": ["%s"], "token_ttl": "5m", "token_max_ttl": "5m"}`+"\n", c.Audience, c.FlyOrg, app, key)
		fmt.Println("EOF")
	}
	app := c.FlyApp[0]
	fmt.Println("\nThen add each app as a workload of its own group (BAO_TOKEN lets this read the public key):")
	fmt.Printf("\n  esec vault group create %s/%s\n", c.FlyOrg, app)
	fmt.Printf("  esec vault access grant %s/%s --env prod --project %s/PROJECT\n", c.FlyOrg, app, c.FlyOrg)
	fmt.Printf("  esec vault group workload %s/%s %s --fly-org %s --fly-app %s \\\n    --openbao-key %s/transit/esec-%s/1 --openbao-role jwt/fly-%s --openbao-audience %s\n", c.FlyOrg, app, app, c.FlyOrg, app, addr, app, app, c.Audience)
	fmt.Println("\nCost: what the OpenBao host costs; keys and decrypts are free. It starts sealed after a restart: unseal it with your key shares.")
	return nil
}

// KMSSetupGCPCmd prints, or runs, the gcloud commands that set up Cloud KMS
// for workloads on Fly.io.
type KMSSetupGCPCmd struct {
	Project  string   `required:"" help:"GCP project id"`
	Location string   `default:"europe-west1" help:"Where the key lives (pick one near your apps)"`
	KeyRing  string   `name:"keyring" default:"esec" help:"Key ring"`
	Key      string   `default:"workloads" help:"Key name: one key may serve every app, or name one per app, such as esec-store with --fly-app store"`
	Pool     string   `default:"esec-workloads" help:"Workload identity pool"`
	FlyOrg   string   `name:"fly-org" required:"" help:"Fly.io organisation slug (fly orgs list)"`
	FlyApp   []string `name:"fly-app" sep:"," required:"" help:"Fly.io apps that may unwrap with the key"`
	Apply    bool     `help:"Run the commands (gcloud must be signed in with rights on the project); default: print them"`
}

// Run implements kms setup gcp.
func (c *KMSSetupGCPCmd) Run(_ *cliCtx) error {
	name := regexp.MustCompile(`^[a-z0-9-]{1,63}$`)
	for _, v := range append([]string{c.Project, c.Location, c.KeyRing, c.Key, c.Pool, c.FlyOrg}, c.FlyApp...) {
		if !name.MatchString(v) {
			return fmt.Errorf("%q: use lowercase letters, digits and dashes", v)
		}
	}
	provider := "fly-" + c.FlyOrg
	if len(provider) > 32 {
		provider = provider[:32]
	}
	// The provider admits the Fly.io organisation's apps; each key's IAM
	// binding names the apps that may decrypt with it, so adding an app
	// needs only its binding.
	condition := fmt.Sprintf("assertion.org_name == '%s'", c.FlyOrg)
	keyPath := []string{"--keyring", c.KeyRing, "--location", c.Location, "--project", c.Project}
	steps := [][]string{
		{"gcloud", "services", "enable", "cloudkms.googleapis.com", "sts.googleapis.com", "iamcredentials.googleapis.com", "--project", c.Project},
		{"gcloud", "kms", "keyrings", "create", c.KeyRing, "--location", c.Location, "--project", c.Project},
		append([]string{"gcloud", "kms", "keys", "create", c.Key, "--purpose", "asymmetric-encryption", "--default-algorithm", "rsa-decrypt-oaep-3072-sha256", "--protection-level", "software"}, keyPath...),
		{"gcloud", "iam", "workload-identity-pools", "create", c.Pool, "--location", "global", "--display-name", "esec vault workloads", "--project", c.Project},
		{"gcloud", "iam", "workload-identity-pools", "providers", "create-oidc", provider, "--location", "global", "--workload-identity-pool", c.Pool,
			"--issuer-uri", team.FlyIssuerBase + "/" + c.FlyOrg, "--attribute-mapping", "google.subject=assertion.sub,attribute.org=assertion.org_name,attribute.app=assertion.app_name",
			"--attribute-condition", condition, "--project", c.Project},
		// Older setups listed the apps in the condition: widen it.
		{"gcloud", "iam", "workload-identity-pools", "providers", "update-oidc", provider, "--location", "global", "--workload-identity-pool", c.Pool,
			"--attribute-condition", condition, "--project", c.Project},
	}
	number := "PROJECT_NUMBER"
	if c.Apply {
		out, err := exec.Command("gcloud", "projects", "describe", c.Project, "--format", "value(projectNumber)").Output()
		if err != nil {
			return fmt.Errorf("gcloud projects describe %s: %w", c.Project, err)
		}
		number = strings.TrimSpace(string(out))
	}
	for _, app := range c.FlyApp {
		member := fmt.Sprintf("principalSet://iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/attribute.app/%s", number, c.Pool, app)
		steps = append(steps, append([]string{"gcloud", "kms", "keys", "add-iam-policy-binding", c.Key, "--member", member, "--role", "roles/cloudkms.cryptoKeyDecrypter"}, keyPath...))
	}
	gcpKey := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/1", c.Project, c.Location, c.KeyRing, c.Key)
	gcpProvider := fmt.Sprintf("projects/%s/locations/global/workloadIdentityPools/%s/providers/%s", number, c.Pool, provider)
	if !c.Apply {
		fmt.Println("# One-time Google Cloud setup (or run this command again with --apply):")
		fmt.Printf("# PROJECT_NUMBER=$(gcloud projects describe %s --format='value(projectNumber)')\n\n", c.Project)
		for _, s := range steps {
			fmt.Println(shellJoin(s))
		}
	} else {
		for _, s := range steps {
			fmt.Println("$ " + shellJoin(s))
			var out bytes.Buffer
			cmd := exec.Command(s[0], s[1:]...)
			cmd.Stdout, cmd.Stderr = io.MultiWriter(os.Stdout, &out), io.MultiWriter(os.Stderr, &out)
			if err := cmd.Run(); err != nil {
				// Running it again for another app finds the key ring,
				// pool and provider there already.
				if strings.Contains(strings.ToLower(out.String()), "already exists") {
					fmt.Println("  (there already)")
					continue
				}
				return fmt.Errorf("%s: %w (fix it and run again)", strings.Join(s[:4], " "), err)
			}
		}
	}
	groups := ""
	if len(c.FlyApp) == 1 && c.Key != "workloads" {
		groups = " --groups ORG/" + c.FlyApp[0]
	}
	fmt.Printf("\nThen approve the key in your organisation (ORG), and set up each app:\n\n  esec vault org kms add ORG %s --gcp-key %s \\\n    --gcp-provider %s%s\n  esec vault org fly-app ORG %s --read ORG/PROJECT:prod --kms %s\n", c.Key, gcpKey, gcpProvider, groups, c.FlyApp[0], c.Key)
	fmt.Println("\nOr on the organisation's web page: Settings › Approve a key, then Workloads › Add a Fly.io app.")
	fmt.Println("\nCost: a software key version is about $0.06 a month, and each workload start makes one decrypt (about $0.03 per 10,000). Token exchange is free.")
	return nil
}

// shellJoin quotes a command for a POSIX shell.
func shellJoin(args []string) string {
	out := make([]string, len(args))
	for i, a := range args {
		if a != "" && !strings.ContainsAny(a, " '\"$&|;<>()*?[]{}\\=,") {
			out[i] = a
			continue
		}
		out[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	return strings.Join(out, " ")
}
