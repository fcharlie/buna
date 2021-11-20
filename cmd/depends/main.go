package main

import (
	"fmt"
	"os"
)

type dependsOption struct {
	files  []string
	toJSON bool
}

// version info
var (
	VERSION     = "1.0"
	BUILDTIME   string
	BUILDCOMMIT string
	BUILDBRANCH string
	GOVERSION   string
	IsDebugMode bool
)

func version() {
	fmt.Fprintf(os.Stdout, `depends - View dependency information of executable files
version:       %s
build branch:  %s
build commit:  %s
build time:    %s
go version:    %s

`, VERSION, BUILDBRANCH, BUILDCOMMIT, BUILDTIME, GOVERSION)

}

func usage() {
	fmt.Fprintf(os.Stdout, `depends - View dependency information of executable files
usage: %s <option> file...
  -h|--help        Show usage text and quit
  -v|--version     Show version number and quit
  -V|--verbose     Make the operation more talkative
  -J|--json        Return information about depends found in a format described json

`, os.Args[0])
}

//-A|--user-agent  Send User-Agent <name> to server

func (d *dependsOption) Invoke(val int, oa, raw string) error {
	switch val {
	case 'h':
		usage()
		os.Exit(0)
	case 'v':
		version()
		os.Exit(0)
	case 'V':
		IsDebugMode = true
	case 'J':
		d.toJSON = true
	}
	return nil
}

func (d *dependsOption) ParseArgv() error {
	var pa ParseArgs
	pa.Add("help", NOARG, 'h')
	pa.Add("version", NOARG, 'v')
	pa.Add("verbose", NOARG, 'V')
	pa.Add("json", NOARG, 'J')
	if err := pa.Execute(os.Args, d); err != nil {
		return err
	}
	d.files = pa.Unresolved()
	return nil
}

// depends scan depends
func main() {
	var d dependsOption
	if err := d.ParseArgv(); err != nil {
		fmt.Fprintf(os.Stderr, "ParseArgv error %v\n", err)
		os.Exit(1)
	}
	if len(d.files) == 0 {
		fmt.Fprintf(os.Stderr, "missing input file\n")
		usage()
		os.Exit(1)
	}
}
