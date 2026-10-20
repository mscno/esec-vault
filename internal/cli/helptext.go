package cli

import "github.com/alecthomas/kong"

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
	"team list": examples(
		"esec vault team                   # your shared projects",
		"esec vault team list --json",
	),
	"team show": examples(
		"esec vault team show                       # in the repository",
		"esec vault team show --project acme/api --json",
	),
	"team create": `Run it in the repository. You become the project's first admin, and every environment key in your keyring for it becomes the project's.

` + examples(
		"esec vault team create",
		"esec vault team create --env dev,prod",
	),
	"team add": `The person signs in first (esec vault login SERVER) and proves their GitHub account (esec vault team prove). Their devices get the keys at their next sync.

` + examples(
		"esec vault team add alice --env dev",
		"esec vault team add bob --admin",
		"esec vault team add carol --env dev --account-key WORD-WORD-...   # without a GitHub SSH key",
	),
	"team set": examples(
		"esec vault team set alice --env dev,staging   # replaces what she reads",
		"esec vault team set alice --admin",
		"esec vault team set alice --no-admin --env dev --yes",
	),
	"team remove": `They stop getting keys at once. Keys they already read stay with them: rotate what they read (team show lists it).

` + examples(
		"esec vault team remove alice",
		"esec vault team remove alice --yes --reason \"left the team\"",
		"esec vault env rotate dev",
	),
	"team sync": `The background service does this by itself; run it to see the result at once.

` + examples("esec vault team sync"),
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
	"group create": `Then let it read a project (group grant) and add machines (group token, group add-machine, or machine join on the machine).

` + examples(
		"esec vault group create acme/production",
		"esec vault group grant acme/production --env prod     # in the project's repository",
	),
	"group grant": `Run as an admin of both the project and the group. --env replaces what the group read before.

` + examples(
		"esec vault group grant acme/production --env prod",
		"esec vault group grant acme/staging --env staging --project acme/api",
	),
	"group token": `Printed once: store it as a secret. Expiry counts from now; --expires never suits app platforms such as Fly.io.

` + examples(
		"esec vault group token acme/production autoscale --expires 90d",
		"fly secrets set ESEC_VAULT_MACHINE_KEY=\"$(esec vault group token acme/production fly --expires never --out -)\"",
	),
	"group add-machine": examples(
		"esec vault group add-machine acme/production web-1 --out web-1.key",
	),
	"group approve": examples(
		"esec vault group approve acme/production",
		"esec vault group approve acme/production --words WORD-WORD-...   # the words the machine shows",
	),
	"group remove": `The group gets a new key at once. Rotate the environments the machine read, unless it was destroyed with its disk (--destroyed).

` + examples(
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
		if d, ok := commandDetails[n.Path()]; ok {
			n.Detail = d
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	walk(app.Node)
}

// examples formats command lines as an indented block.
func examples(lines ...string) string {
	out := "Examples:\n\n"
	for _, l := range lines {
		out += "    " + l + "\n"
	}
	return out
}
