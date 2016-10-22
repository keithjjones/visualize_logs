# visualize_logs

A Python library to provide log visualization. 

Currently supports the following types of logs:
  - ProcMon CSV
  	- Be sure to either turn on all columns or use [DetailedProcmonConfiguration.pmc](ProcMon/Configuration File/DetailedProcmonConfiguration.pmc)

# Requirements

Graphviz must be installed and available in your path (dot, neato, etc..)
  - http://www.graphviz.org/

To install Graphviz correctly on a Mac, you will probably want to run the following command:

```
brew install graphviz --with-gts
```

This program was written with Python 3 on a Mac and Windows 7.  It should work with Python 2 and other OS's, but it has not been tested
extensively.  Please file an issue if you have problems running it somewhere.  I use Windows less than I use a Mac, so your mileage may
vary.

# Example Output

Coming soon!

# Usage

Coming soon!

## ProcMon CSV Command Line Tool

```
# plotprocmoncsv -h
usage: plotprocmoncsv [-h] [-f HTMLFile] [-pa] [-pfw] [-pfr] [-pfd] [-pfn]
                      [-pt] [-pus] [-pur] [-sa] [-sp] [-st] [-su] [-sf] [-sh]
                      ProcMonCSVFile

Application to graph ProcMon CSV files

positional arguments:
  ProcMonCSVFile        ProcMon CSV file

optional arguments:
  -h, --help            show this help message and exit
  -f HTMLFile, --file HTMLFile
                        Create the log file.
  -pa, --plotall        Plot all aspects
  -pfw, --plotfilewrites
                        Plot file writes
  -pfr, --plotfilereads
                        Plot file reads
  -pfd, --plotfiledeletes
                        Plot file deletes
  -pfn, --plotfilerenames
                        Plot file renames
  -pt, --plottcpconnects
                        Plot TCP connects
  -pus, --plotudpsends  Plot UDP sends
  -pur, --plotudprecvs  Plot UDP receives
  -sa, --showalllabels  Show all labels
  -sp, --showproclabels
                        Show process labels
  -st, --showtcplabels  Show TCP labels
  -su, --showudplabels  Show UDP labels
  -sf, --showfilelabels
                        Show file labels
  -sh, --showhostlabels
                        Show host labels
```

You can run it like this:

```
# plotprocmoncsv -pa -sp -st -sh /Source/Procmon\ CSV/wwwlgoogle.CSV 
Reading log: /Source/Procmon CSV/wwwlgoogle.CSV
Plotting log: /Source/Procmon CSV/wwwlgoogle.CSV
```

... and then your plot appears in your web browser!  It is also saved to `procmoncsv.html`.

## ProcMon Logs

The best use case is if you start your ProcMon capture before you run the file you are analyzing.  If a process 
is not started the associated network connections may not be connected to the process in the plot.  I also could
not get ProcMon to capture TCP data when WinPCAP was installed.  You may not want to install WinPCAP if you are
interested in TCP data.

This this library feels like it is taking a long time, it is likely that you are trying to import a lot of ProcMon
data.  You can always filter your data and save it as a CSV showing just the events you want to graph.

### Sample data:

You can find some sample CSV from ProcMon in the [ProcMon/Sample Data] (ProcMon/Sample Data/) directory.

# Documentation

Coming soon!

The library documentation can be found at:  https://keithjjones.github.io/visualize_logs.github.io/

# Resources

- ProcMon
  - https://technet.microsoft.com/en-us/sysinternals/processmonitor.aspx

# Similar Projects

These projects are very similar to this one and are worth trying if you are
unfamiliar with them.  They were the inspiration behind this project.  This project
was meant to compliment these tools, not replace them.

- Noriben
  - https://github.com/Rurik/Noriben
- ProcDot
  - http://www.procdot.com/

# License:

This application is covered by the Creative Commons BY-SA license.

- https://creativecommons.org/licenses/by-sa/4.0/
- https://creativecommons.org/licenses/by-sa/4.0/legalcode

# Contributing:

If you would like to contribute you can fork this repository, make your changes, and
then send me a pull request to my "dev" branch.