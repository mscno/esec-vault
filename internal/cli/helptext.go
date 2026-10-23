package cli

import (
	"strings"

	"github.com/alecthomas/kong"
)

// commandDetails are the explanations and examples "esec vault <command>
// --help" shows below a command's one-line help, by command path. Kept
// apart from the commands so they read as one place to look things up.
var commandDetails = map[string]string{
	"setup": examples(
		"esec vault setup                  # identity, recovery phrase, backup destination, background service",
		"esec vault setup --no-daemon      # without the background service",
	),
	"login": `Signs in with GitHub in the browser. A new device then waits for one of your devices to approve it (esec vault devices approve), or unlocks itself with --recover or --ssh-agent.

` + examples(
		"esec vault login https://vault.example.com",
		"esec vault login --no-browser                     # print the sign-in link instead",
		"esec vault login --ssh-agent                      # unlock with an SSH key set up by agent-unlock",
		"esec vault login --account-key WORD-WORD-...      # check the account key without asking",
	),
	"status": examples(
		"esec vault status",
		"esec vault status --json          # for scripts and agents",
	),
	"project init": `Writes .esec-project, creates a key per environment in your global keyring, and secrets files encrypted to them. Commit the project file and the secrets files; the keys never enter the repository.

` + examples(
		"esec vault project init acme/api                    # .env.dev with a dev key",
		"esec vault project init acme/api --env dev,prod -f ejson",
	),
	"env add": `Prints the key's public half (ESEC_PUBLIC_KEY=...) for the new secrets file. In a shared project it also becomes the project's key, sent to those who read it.

` + examples(
		"esec vault env add prod",
	),
	"env list": examples(
		"esec vault env list",
		"esec vault env list --json",
	),
	"env rotate": `Makes a new key, re-encrypts every secrets file of the environment under the project directory, and in a shared project sends the new key to everyone who reads it. Rotate after someone who read it leaves. Change the secrets' values too where that matters: anyone who read them may have kept them.

` + examples(
		"esec vault env rotate prod",
		"esec vault env rotate prod --yes --project acme/api",
	),
	"run": `Asks the background service for the key, so no key file sits on disk. Without the service, use esec run.

` + examples(
		"esec vault run dev -- npm start",
		"esec vault run prod -- ./deploy.sh",
	),
	"access list": examples(
		"esec vault access                 # your shared projects",
		"esec vault access list --json",
	),
	"access show": examples(
		"esec vault access show            # in the repository",
		"esec vault access show --project acme/api --json",
	),
	"access create": `Run it in the repository. You become the project's first admin, and every environment key in your keyring for it becomes the project's.

` + examples(
		"esec vault access create",
		"esec vault access create --env dev,prod",
	),
	"access add": `The person signs in first (esec vault login SERVER) and proves their GitHub account (esec vault access prove). Their devices get the keys at their next sync.

` + examples(
		"esec vault access add alice --env dev",
		"esec vault access add bob --admin",
		"esec vault access add carol --env dev --account-key WORD-WORD-...   # without a GitHub SSH key",
	),
	"access grant": `A GitHub login adds or extends a person; an org/name adds or extends a group, whose people and machines then read the environments too. New environments are added to what they read already.

` + examples(
		"esec vault access grant alice --env dev",
		"esec vault access grant alice --env staging       # now dev and staging",
		"esec vault access grant bob --admin",
		"esec vault access grant acme/backend --env dev,staging",
		"esec vault access grant acme/production --env prod --project acme/api --json",
		"esec vault access grant alice --env prod --for 8h     # emergency access that ends by itself",
	),
	"access request": `Anyone signed in may ask; the project's admins see it on its page, on their overview and with access requests. An admin grants it from a device or a passkey.

` + examples(
		"esec vault access request --env staging",
		"esec vault access request --env prod --reason \"on call this week\" --project acme/api",
	),
	"access requests": examples(
		"esec vault access requests                    # to answer, and your own",
		"esec vault access requests --grant 12",
		"esec vault access requests --deny 13",
		"esec vault access requests --json",
	),
	"access revoke": `Without --env, the person leaves the project, or the group stops reading it. Keys they read before stay with them: rotate those environments (the command lists them).

` + examples(
		"esec vault access revoke alice --env prod",
		"esec vault access revoke alice --yes --reason \"left the team\"",
		"esec vault access revoke acme/backend --yes",
	),
	"access offboard": `Lists every project and group the person reads from that you can see, takes them out of each one you administer, and lists the environments to rotate.

` + examples(
		"esec vault access offboard alice --dry-run",
		"esec vault access offboard alice --yes --json",
	),
	"access review": `Asks about each member, group and machine (admins are kept), takes access away from those you say, and records the review on the server, where an organisation's policy may ask for one every so many days.

` + examples(
		"esec vault access review",
		"esec vault access review --remove bob,machine:old-ci --yes --project acme/api",
		"esec vault access review --keep-all",
	),
	"org": `An organisation is the acme of acme/store. Set it up (org create) to give it a signed chain: its people, the KMS keys its workloads may use, and its rules, all signed on admins' devices. Then only its people create projects and groups named acme/..., removing someone from it takes them out of every project and group of it, and devices wrap workload keys only with approved KMS keys. Everything here is on its web page too (/orgs/ORG).

` + examples(
		"esec vault org                    # your organisations",
		"esec vault org acme",
		"esec vault org acme --json",
	),
	"org create": `Signs the organisation's first link with you as its admin. Anyone may set up a name nothing is named after yet; once projects or groups are, an admin of one of them (or a server admin).

` + examples(
		"esec vault org create acme",
	),
	"org trust": `A server could show a made-up chain for an organisation, and anyone may set one up for a name nothing is named after yet. So a device applies an organisation's removals, and wraps workload keys with the keys it approved by name, only once it is anchored: this account signed in it, or you compared its fingerprint with an admin's here.

` + examples(
		"esec vault org trust acme",
		"esec vault org trust acme --fingerprint word-word-word-word-word-word-word-word",
	),
	"org add": `Checks the person like a new project member (their GitHub SSH proof, or the account key words they read to you). Belonging gives no keys by itself.

` + examples(
		"esec vault org add acme alice",
		"esec vault org add acme bob --admin",
		"esec vault org add acme carol --account-key 'word-word-...'",
	),
	"org remove": `Removes them from the organisation, then takes them out of every project and group of it you administer, giving groups a new key; the devices of the other admins do the same for theirs on their next sync. Rotate what they could read afterwards. Your own login leaves the organisation.

` + examples(
		"esec vault org remove acme alice --yes",
	),
	"org kms add": `Reads the key's public half from the KMS itself (gcloud, or OpenBao with BAO_TOKEN; the token goes only to BAO_ADDR), so the key is the one its name says, and approves it for the organisation's workloads. --groups limits it to some groups, such as the one group of the app a per-app key is for.

` + examples(
		"esec vault org kms add acme gcp-prod --gcp-key projects/acme-vault/locations/europe-west1/keyRings/esec/cryptoKeys/workloads/cryptoKeyVersions/1 --gcp-provider projects/123/locations/global/workloadIdentityPools/esec-workloads/providers/fly-acme --default",
		"esec vault org kms add acme fly-store --openbao-key https://bao.acme.dev/transit/esec-store/1 --openbao-role jwt/fly-store --groups acme/store",
	),
	"org set": `Flags not given stay as they are. Devices check the rules when they sign; the server when it stores changes, together with its admins' own policy (the stricter applies).

` + examples(
		"esec vault org set acme --members-only --require-github-proof",
		"esec vault org set acme --max-token-days 30 --review-days 90",
		"esec vault org set acme --fly-org acme --default-kms gcp-prod",
	),
	"org fly-app": `Creates the app's group (ORG/APP) when it is missing, lets it read what --read names (you must administer those projects), and adds the app as a workload bound to Fly.io's OIDC tokens for it, wrapped with an approved KMS key. Prints the descriptor for fly.toml. Running it again changes nothing that is in place.

` + examples(
		"esec vault org fly-app acme store --read acme/store:prod",
		"esec vault org fly-app acme api --read acme/api:prod --read acme/shared:prod --kms fly-api",
	),
	"access handover": `Only a device signs who is an admin. The web page's Hand over admin proposes the same changes for a device to sign.

` + examples(
		"esec vault access handover alice",
		"esec vault access handover alice --step-down     # then you are a member who reads everything",
	),
	"access move": `Renames a project: a new chain under the new id, with the same environment keys (the encrypted files stay as they are) and people, who get the keys again; the old project is archived, naming the new one, and members' devices follow it. Groups you administer move too; machines, and other admins' groups, are listed to add again. Then set ESEC_PROJECT in the repository's .esec-project.

` + examples(
		"esec vault access move acme/shop",
		"esec vault access move acme/shop --project acme/store --yes",
	),
	"access archive": `An archived project sends no keys and changes in nothing but members leaving; its keys stay in keyrings. Delete it from the server afterwards with access delete.

` + examples(
		"esec vault access archive --reason \"replaced by acme/shop\"",
		"esec vault access archive --undo",
	),
	"access delete": examples(
		"esec vault access archive && esec vault access delete --yes",
	),
	"access set": examples(
		"esec vault access set alice --env dev,staging   # replaces what they read",
		"esec vault access set alice --admin",
		"esec vault access set alice --no-admin --env dev --yes",
	),
	"access remove": `They stop getting keys at once. Keys they already read stay with them: rotate what they read (access show lists it).

` + examples(
		"esec vault access remove alice",
		"esec vault access remove alice --yes --reason \"left the team\"",
		"esec vault env rotate dev",
	),
	"access sync": `The background service does this by itself; run it to see the result at once.

` + examples("esec vault access sync"),
	"changes": `Changes made on the vault's web pages are signed by one of your devices before they take effect, since the server could have invented them. Each is shown and asked about; --yes signs removals without asking, never anything that gives access.

` + examples(
		"esec vault changes                # review and sign",
		"esec vault changes --list         # only look",
		"esec vault changes --json         # for scripts and agents",
		"esec vault changes --yes          # also sign removals unasked",
	),
	"delegate server": examples(
		"esec vault delegate server        # removals made on the web apply at once",
		"esec vault delegate server --off",
	),
	"devices list": examples(
		"esec vault devices",
		"esec vault devices list --json",
	),
	"devices approve": `Compare the words the new device shows with the words shown here before approving it.

` + examples(
		"esec vault devices approve",
		"esec vault devices approve d_abc123",
	),
	"machine create": `Prints the machine's key once: give it to the job as ESEC_VAULT_MACHINE_KEY. For machines that come and go, or several servers, use a machine group instead (esec vault group).

` + examples(
		"esec vault machine create deploy --env prod",
		"esec vault machine create ci --env dev --github-repo acme/api --github-ref refs/heads/main",
		"esec vault machine create ci --env dev --out - | gh secret set ESEC_VAULT_MACHINE_KEY",
	),
	"machine list": examples(
		"esec vault machine list",
		"esec vault machine list --project acme/api --json",
	),
	"machine join": `Run on the machine itself. With an enrollment token it joins at once; without one it waits until an admin approves it (esec vault group approve).

` + examples(
		"esec vault machine join --token @/run/secrets/enroll",
		"esec vault machine join acme/production --server https://vault.example.com --fingerprint WORD-WORD-...",
	),
	"machine whoami": examples(
		"esec vault machine whoami",
		"esec vault machine whoami --json   # names only, never keys",
	),
	"machine run": `Sets the machine's keys as ESEC_PRIVATE_KEY_... variables, so esec in the command decrypts the secrets files.

` + examples(
		"esec vault machine run -- esec run prod -- ./server",
		"esec vault machine run --env prod -- ./deploy.sh",
	),
	"machine env": `Prints private keys: send the output only where they belong.

` + examples(
		"esec vault machine env --format github     # in a GitHub Actions step",
		"eval \"$(esec vault machine env)\"",
	),
	"group list": examples(
		"esec vault group                  # your machine groups",
		"esec vault group list --json",
	),
	"group show": examples(
		"esec vault group show acme/production",
		"esec vault group show acme/production --json",
	),
	"group create": `A group holds people (a team, such as acme/backend), machines (servers, such as acme/production), or both. Then let it read a project (access grant) and add people (group add) or machines (group token, group add-machine, or machine join on the machine).

` + examples(
		"esec vault group create acme/backend",
		"esec vault group add acme/backend alice",
		"esec vault access grant acme/backend --env dev,staging   # in the project's repository",
	),
	"group add": `The person signs in first and proves their GitHub account (esec vault access prove). The group key is sealed to them; their devices then take in the keys of every project the group reads, after they accept each project once.

` + examples(
		"esec vault group add acme/backend alice",
		"esec vault group add acme/backend carol --account-key WORD-WORD-...",
	),
	"group leave": examples("esec vault group leave acme/backend"),
	"group grant": `Run as an admin of both the project and the group. --env replaces what the group read before.

` + examples(
		"esec vault group grant acme/production --env prod",
		"esec vault group grant acme/staging --env staging --project acme/api",
	),
	"group token": `Printed once: store it as a secret. Expiry counts from now; --expires never suits app platforms such as Fly.io.

` + examples(
		"esec vault group token acme/production autoscale --expires 90d",
		"esec vault group token acme/production fly-store --expires 90d --fly-org acme --fly-app store",
		"fly secrets set ESEC_VAULT_MACHINE_KEY=\"$(esec vault group token acme/production fly --expires never --out -)\"",
	),
	"group add-machine": examples(
		"esec vault group add-machine acme/production web-1 --out web-1.key",
	),
	"group approve": examples(
		"esec vault group approve acme/production",
		"esec vault group approve acme/production --words WORD-WORD-...   # the words the machine shows",
	),
	"group remove": `Removes a person (by GitHub login) or a machine or token. The group gets a new key at once. Rotate the environments they read, unless a machine was destroyed with its disk (--destroyed).

` + examples(
		"esec vault group remove acme/backend alice",
		"esec vault group remove acme/production web-3",
		"esec vault group remove acme/production web-4 --destroyed --yes",
	),
	"backup": examples(
		"esec vault backup",
		"esec vault backup --push          # also upload to the default remote",
	),
	"recover": `On a new machine, with your 24-word recovery phrase and a backup from your remote or a file.

` + examples(
		"esec vault recover",
		"esec vault recover --file vault-backup.esec",
	),
}

// addDetails puts commandDetails on the command nodes.
func addDetails(app *kong.Application) {
	var walk func(n *kong.Node)
	walk = func(n *kong.Node) {
		if d, ok := commandDetails[commandPath(n)]; ok {
			n.Detail = d
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	walk(app.Node)
}

// commandPath is a command's path by name ("access add"), without the
// aliases kong's Path adds.
func commandPath(n *kong.Node) string {
	var parts []string
	for ; n != nil && n.Type == kong.CommandNode; n = n.Parent {
		parts = append([]string{n.Name}, parts...)
	}
	return strings.Join(parts, " ")
}

// examples formats command lines as an indented block.
func examples(lines ...string) string {
	out := "Examples:\n\n"
	for _, l := range lines {
		out += "    " + l + "\n"
	}
	return out
}
