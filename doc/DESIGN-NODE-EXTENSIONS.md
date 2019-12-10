# Node Extensions Design

Biggest problem with being a node-centric CA utility is
the frequent inclusion of child node's X509v3 extension
in its parent node's OpenSSL configuration file (as
found in numerous openssl.cnf examples.

    openssl ca -config root-ca.cnf  # has both parent and child CAs' stuff

This approach prevents the simple setup of this single
OpenSSL configuration file because they "historically"
contains both X509v3 settings of a parent CA node and
all of its related child CA nodes.

To better keep the node-centric design approach, I
opted to keep all extension settings into a separate file,
for later auto-inclusion by other node's commands.

This separate extension file has a unique filename
that is denoted as "<parent_ca_node>_<child_ca_node>.cnf".

This way, if we execute:

    tls-ca-manage -p root signing

The 'root-ca_signing-ca.cnf extension file then
gets magically included during the later cert-signing
('openssl ca') of Signing CA to Root CA command.

Signing a CA often entails using that config
file of its parent CA:

    openssl genkey -config signing-ca.cnf ...
    openssl req    -config signing-ca.cnf ...

    # After genpkey and req command on Signing CA certs

    openssl ca     -config root-ca.cnf \
        -extfile root-ca_signing-ca.cnf \
        ...

Remember, many openssl.cnf examples have folded those
child node's ca-related extensions into this parent's
config file: Not so here.

In here, these extension (-extfile option) files
denote the direct relationship between any two CAs,
whether they be root, intermediate and/or end/signing
CA types.

I'm going in circles, aren't I: let's wrap this up...

This simpler approach cuts down the complexity of
tracking all node relationships to just maintaining
this singular node-centric design; using two
separate config files:

   * main CA config file (much like openssl.cnf)
   * inter-CA config file (X509v3 extension)

Not revealed by its scant documentation on OpenSSL's part,
this is the primary reason for having '-extfile' option.
