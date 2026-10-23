package cli

import (
	"context"
	"errors"
	"fmt"
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
	PublicKey         string `name:"public-key" type:"existingfile" help:"The KMS key's public key (PEM); default: ask gcloud for it"`
	Out               string `help:"Write the workload's descriptor to this file too"`
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
	if c.GCPKey == "" || c.GCPProvider == "" {
		return errors.New("name the KMS key and its identity federation: --gcp-key and --gcp-provider (esec vault kms setup gcp prints both)")
	}
	key := kms.Key{Provider: "gcp", Name: c.GCPKey, Audience: c.GCPProvider, Principal: c.GCPServiceAccount}
	pemText, err := c.publicKey()
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
	fmt.Printf("  Its group key is wrapped with %s; only Cloud KMS can unwrap it, for that workload.\n", key.Name)
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

var gcpKeyVersion = regexp.MustCompile(`^projects/([^/]+)/locations/([^/]+)/keyRings/([^/]+)/cryptoKeys/([^/]+)/cryptoKeyVersions/([^/]+)$`)

// publicKey reads the key's public half from --public-key, or from gcloud.
func (c *GroupWorkloadCmd) publicKey() ([]byte, error) {
	if c.PublicKey != "" {
		return os.ReadFile(c.PublicKey)
	}
	m := gcpKeyVersion.FindStringSubmatch(c.GCPKey)
	if m == nil {
		return nil, errors.New("--gcp-key is a key version: projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/N")
	}
	bg, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	out, err := exec.CommandContext(bg, "gcloud", "kms", "keys", "versions", "get-public-key", m[5], "--key", m[4], "--keyring", m[3], "--location", m[2], "--project", m[1], "--output-file", "-").Output()
	if err != nil {
		return nil, fmt.Errorf("ask gcloud for the key's public key (or pass --public-key FILE): %w", err)
	}
	return out, nil
}

// KMSCmd sets up external KMS keys for workloads.
type KMSCmd struct {
	Setup KMSSetupCmd `cmd:"" help:"Set up a KMS key and identity federation for workloads with no secret."`
}

// KMSSetupCmd sets up a provider.
type KMSSetupCmd struct {
	GCP KMSSetupGCPCmd `cmd:"" name:"gcp" help:"Google Cloud: a Cloud KMS key, and workload identity federation trusting Fly.io's OIDC tokens."`
}

// KMSSetupGCPCmd prints, or runs, the gcloud commands that set up Cloud KMS
// for workloads on Fly.io.
type KMSSetupGCPCmd struct {
	Project  string   `required:"" help:"GCP project id"`
	Location string   `default:"europe-west1" help:"Where the key lives (pick one near your apps)"`
	KeyRing  string   `name:"keyring" default:"esec" help:"Key ring"`
	Key      string   `default:"workloads" help:"Key name: one key serves every workload"`
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
	quoted := make([]string, len(c.FlyApp))
	for i, a := range c.FlyApp {
		quoted[i] = "'" + a + "'"
	}
	condition := fmt.Sprintf("assertion.org_name == '%s' && assertion.app_name in [%s]", c.FlyOrg, strings.Join(quoted, ", "))
	keyPath := []string{"--keyring", c.KeyRing, "--location", c.Location, "--project", c.Project}
	steps := [][]string{
		{"gcloud", "services", "enable", "cloudkms.googleapis.com", "sts.googleapis.com", "iamcredentials.googleapis.com", "--project", c.Project},
		{"gcloud", "kms", "keyrings", "create", c.KeyRing, "--location", c.Location, "--project", c.Project},
		append([]string{"gcloud", "kms", "keys", "create", c.Key, "--purpose", "asymmetric-encryption", "--default-algorithm", "rsa-decrypt-oaep-3072-sha256", "--protection-level", "software"}, keyPath...),
		{"gcloud", "iam", "workload-identity-pools", "create", c.Pool, "--location", "global", "--display-name", "esec vault workloads", "--project", c.Project},
		{"gcloud", "iam", "workload-identity-pools", "providers", "create-oidc", provider, "--location", "global", "--workload-identity-pool", c.Pool,
			"--issuer-uri", team.FlyIssuerBase + "/" + c.FlyOrg, "--attribute-mapping", "google.subject=assertion.sub,attribute.org=assertion.org_name,attribute.app=assertion.app_name",
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
			cmd := exec.Command(s[0], s[1:]...)
			cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("%s: %w (fix it and run again; steps that exist already fail harmlessly)", strings.Join(s[:4], " "), err)
			}
		}
	}
	fmt.Printf("\nThen add each app as a workload of its group:\n\n  esec vault group workload acme/production %s --fly-org %s --fly-app %s \\\n    --gcp-key %s \\\n    --gcp-provider %s\n", c.FlyApp[0], c.FlyOrg, c.FlyApp[0], gcpKey, gcpProvider)
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
