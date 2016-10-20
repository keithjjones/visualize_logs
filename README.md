# visualize_logs

A Python library to provide log visualization. 

Currently supports the following types of logs:
  - ProcMon CSV
  	- Be sure to either turn on all columns or use [DetailedProcmonConfiguration.pmc](ProcMon/Configuration File/DetailedProcmonConfiguration.pmc)

# Requirements

Graphviz must be installed and available in your path (dot, neato, etc..)
  - http://www.graphviz.org/

This program was written with Python 3 on a Mac and Windows 7.  It should work with Python 2 and other OS's, but it has not been tested
extensively.  Please file an issue if you have problems running it somewhere.

# Example Output

Coming soon!

# Usage

Coming soon!

## ProcMon Logs

The best use case is if you start your ProcMon capture before you run the file you are analyzing.  If a process 
is not started the associated network connections may not be connected to the process in the plot.

This this library feels like it is taking a long time, it is likely that you are trying to import a lot of ProcMon
data.  You can always filter your data and save it as a CSV showing just the events you want to graph.

### Sample data:

You can find some sample CSV from ProcMon in the [ProcMon\Sample Data] (https://github.com/keithjjones/visualize_logs/tree/master/ProcMon/Sample%20Data) directory.

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