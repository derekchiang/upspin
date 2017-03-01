package main

import (
	"flag"
	"fmt"

	"upspin.io/access"
	"upspin.io/upspin"
)

func (s *State) access(args ...string) {
	const help = `
Access updates an Access file.  One needs to use either the "-grant"
or the "-revoke" flag with this command, but not both.  These flags
specify whether the following rights are to be added or removed from
the Access file.

The first argument is a comma-separated list of rights that will be
added or removed. Note that you may use '*' to signify "all rights."
However, make sure to wrap '*' in single or double quotes; otherwise
the shell might interpret it as a wildcard matching all files in the
current directory.

The final argument is the Access file to be updated.  The other arguments are the usernames that this command will apply to.

Examples:

# Grant "read" and "list" rights to the user ann@example.com to my root:

upspin -grant read,list ann@example.com me@example.com/Access

# Grant the "write" right to the users ann@example.com and bob@example.com
# to the subdirectory "photos" under my root:

upspin -grant write ann@example.com bob@example.com me@example.com/photos/Access

# Revoke all rights of the user ann@example.com to my root:

upspin -revoke '*' ann@example.com me@example.com/Access
`

	fs := flag.NewFlagSet("access", flag.ExitOnError)
	grant := fs.Bool("grant", false, "")
	revoke := fs.Bool("revoke", false, "")
	s.parseFlags(fs, args, help, "access (-grant | -revoke) right[,right2,right3...] user [user2 user3...] path/Access")

	if !*grant && !*revoke {
		s.exitf("either the -grant or the -revoke flag needs to be provided")
	}

	args = fs.Args()
	if len(args) < 3 {
		fs.Usage()
	}

	//rights := args[0]
	accessPath := upspin.PathName(args[len(args)-1])
	//users := args[1 : len(args)-1]

	if !access.IsAccessFile(accessPath) {
		s.exitf("not an Access file: %s", accessPath)
	}

	entry, err := s.DirServer(accessPath).Lookup(accessPath)
	if err != nil {
		s.exit(err)
	}

	// Parse the current Access file to ensure that it's not malformed
	accessBytes := s.readOrExit(s.client, entry.Name)

	access, err := access.Parse(upspin.PathName(accessPath), accessBytes)
	fmt.Println(string(access.Marshal()))
}
