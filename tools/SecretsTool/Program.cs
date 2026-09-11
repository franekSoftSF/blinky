using Blinky.Secrets;

// Provisions the token the API reads its master secrets out of.
//
// A tool rather than something the service does at start, for the reason in
// Pkcs11Provisioning: creating objects is the one operation that writes to a
// token, and it should be a thing a person did once and can point at, not
// something that happened during a restart nobody watched.
//
// Nothing here is specific to a software token. The same four commands
// provision a device, except init-token, which real hardware is initialised
// for by whoever owns it.

try
{
    return Run(args);
}
catch (KeyUnavailableException e)
{
    Console.Error.WriteLine(e.Message);
    return 1;
}

static int Run(string[] args)
{
    if (args.Length == 0)
    {
        return Usage();
    }

    var module = Option(args, "--module")
                 ?? Environment.GetEnvironmentVariable("BLINKY_PKCS11_MODULE")
                 ?? "/usr/lib/softhsm/libsofthsm2.so";

    var token = Option(args, "--token") ?? "blinky";

    switch (args[0])
    {
        case "init-token":
        {
            var soPin = Required(args, "--so-pin");
            var pin = Required(args, "--pin");

            Pkcs11Provisioning.InitialiseToken(module, token, soPin, pin);

            Console.WriteLine($"Initialised token {token} in {module}.");

            return 0;
        }

        case "generate":
        {
            using var provisioning = new Pkcs11Provisioning(module, token, Required(args, "--pin"));

            var key = Key(args);

            provisioning.Generate(key);

            Console.WriteLine($"Generated {key.Label} inside the token. Nothing outside it has "
                              + "ever seen this value.");

            return 0;
        }

        case "import":
        {
            using var provisioning = new Pkcs11Provisioning(module, token, Required(args, "--pin"));

            var key = Key(args);
            var master = Convert.FromBase64String(Required(args, "--master"));

            provisioning.Import(key, master);

            Console.WriteLine($"Imported the extract of the configured master as {key.Label}.");
            Console.WriteLine("Every card already in the field keeps the management key it has: "
                              + "the derivation is unchanged, only where it happens is.");
            Console.WriteLine("Remove the master from this deployment's configuration now, and "
                              + "keep a copy of it somewhere this host cannot reach.");

            return 0;
        }

        case "list":
        {
            using var provisioning = new Pkcs11Provisioning(module, token, Required(args, "--pin"));

            var keys = provisioning.List();

            if (keys.Count == 0)
            {
                Console.WriteLine($"Token {token} holds no Blinky keys.");

                return 0;
            }

            foreach (var key in keys)
            {
                var custody = key is { Sensitive: true, Extractable: false }
                    ? "sealed"
                    : "CAN BE READ OUT";

                Console.WriteLine($"{key.Label}  {custody}");
            }

            return 0;
        }

        default:
            return Usage();
    }
}

static KeyRef Key(string[] args)
{
    var purpose = Required(args, "--purpose");

    if (!Enum.TryParse<KeyPurpose>(purpose, ignoreCase: true, out var parsed))
    {
        throw new KeyUnavailableException(
            $"{purpose} is not a purpose. One of: {string.Join(", ", Enum.GetNames<KeyPurpose>())}");
    }

    var version = Option(args, "--version") ?? "1";

    return new KeyRef(parsed, int.Parse(version, System.Globalization.CultureInfo.InvariantCulture));
}

static string? Option(string[] args, string name)
{
    var index = Array.IndexOf(args, name);

    return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
}

static string Required(string[] args, string name) =>
    Option(args, name) ?? throw new KeyUnavailableException($"{name} is required.");

static int Usage()
{
    Console.Error.WriteLine("""
        Provisions Blinky's master secrets into a PKCS#11 token.

          init-token --so-pin S --pin P
              Creates the token. Software tokens only; a device is initialised
              by its own tooling.

          generate --pin P --purpose ManagementKeyMaster|PukKek [--version N]
              A new key, made inside the token and unable to leave it. For a
              deployment with no cards in the field.

          import --pin P --purpose ... [--version N] --master BASE64
              Brings an existing configured master in, so that every card keeps
              the management key it already has. For a deployment upgrading.

          list --pin P
              What the token holds, and whether it would hand any of it out.

        Everywhere: --module PATH (or BLINKY_PKCS11_MODULE), --token LABEL.
        """);

    return 2;
}
