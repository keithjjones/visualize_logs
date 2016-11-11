#
# INCLUDES
#

# Required for complex command line argument parsing.
import argparse
# For paths
import os
# Required for plotting logs
from Visualize_Logs.objects.ProcMonCSV \
    import ProcMonCSV as ProcMonCSV
from Visualize_Logs.objects.CuckooJSONReport \
    import CuckooJSONReport as CuckooJSONReport


#
# Main function for plotcuckoojson
#
def plotcuckoojson():
    #
    # Command line args
    #
    parser = argparse.ArgumentParser(
        description='Application to graph cuckoo-modified JSON reports')

    parser.add_argument('CuckooJSONReportFile',
                        help='cuckoo-modified JSON report file')

    parser.add_argument('-f',
                        '--file', metavar='HTMLFile',
                        default='cuckoojson.html',
                        help='Create the html report. Default name '
                        'is cuckoojson.html')

    parser.add_argument('-t',
                        '--title',
                        help='The title for the plot')

    parser.add_argument('-na',
                        '--nonetwork', action='store_true',
                        help='Turn off all network activity')

    parser.add_argument('-fa',
                        '--nofiles', action='store_true',
                        help='Turn off all file activity')

    parser.add_argument('-fc',
                        '--nofilecreates', action='store_true',
                        help='Turn off file create activity')

    parser.add_argument('-fm',
                        '--nofilemoves', action='store_true',
                        help='Turn off file move activity')

    parser.add_argument('-fp',
                        '--nofilecopies', action='store_true',
                        help='Turn off file copy activity')

    parser.add_argument('-fd',
                        '--nofiledeletes', action='store_true',
                        help='Turn off file delete activity')

    parser.add_argument('-fw',
                        '--nofilewrites', action='store_true',
                        help='Turn off file write activity')

    parser.add_argument('-fr',
                        '--nofilereads', action='store_true',
                        help='Turn off file read activity')

    parser.add_argument('-ra',
                        '--noregistry', action='store_true',
                        help='Turn off all registry activity')

    parser.add_argument('-rc',
                        '--noregcreates', action='store_true',
                        help='Turn off registry create activity')

    parser.add_argument('-rd',
                        '--noregdeletes', action='store_true',
                        help='Turn off registry delete activity')

    parser.add_argument('-rw',
                        '--noregwrites', action='store_true',
                        help='Turn off registry write activity')

    parser.add_argument('-rr',
                        '--noregreads', action='store_true',
                        help='Turn off registry read activity')

    parser.add_argument('-ignpaths',
                        '--ignorepathsfile', metavar='IgnPathsFile.txt',
                        help='File containing regular expressions to ignore '
                        'for files and registry.  One RE per line.')

    parser.add_argument('-inclpaths',
                        '--includepathsfile', metavar='InclPathsFile.txt',
                        help='File containing regular expressions to include '
                        'for files and registry.  Overrides ignores. '
                        'One RE per line.')

    parser.add_argument('-gp',
                        '--graphvizprog', default='sfdp',
                        help='The graphviz layout program to use.  Valid '
                             'options are dot, neato, twopi, circo, fdp, '
                             'sfdp, patchwork and osage.  Research the '
                             'graphviz website for more information on '
                             'these types of layouts.  IF YOU SUPPLY AN '
                             'INVALID VALUE THIS PROGRAM WILL NOT WORK! '
                             'Default: sfdp')

    # Parse command line arguments.
    args = parser.parse_args()

    jsonfile = args.CuckooJSONReportFile
    filename = args.file

    if not os.path.exists(jsonfile):
        print('File does not exist: {0}'.format(jsonfile))
        exit(1)

    if args.includepathsfile is not None:
        inclfile = args.includepathsfile
        if not os.path.exists(inclfile):
            print('Include file does not exist: {0}'.format(inclfile))
            exit(1)
        with open(inclfile) as infile:
            try:
                includepaths = infile.read().splitlines()
            except:
                print('ERROR:  File problem: {0}'.format(inclfile))
                exit(1)
    else:
        includepaths = None

    if args.ignorepathsfile is not None:
        ignfile = args.ignorepathsfile
        if not os.path.exists(ignfile):
            print('Ignore file does not exist: {0}'.format(ignfile))
            exit(1)
        with open(ignfile) as infile:
            try:
                ignorepaths = infile.read().splitlines()
            except:
                print('ERROR:  File problem: {0}'.format(ignfile))
                exit(1)
    else:
        ignorepaths = None

    print('Reading log: {0}'.format(jsonfile))
    vl = CuckooJSONReport(jsonfile, plotnetwork=not(args.nonetwork),
                          plotfiles=not(args.nofiles),
                          plotfilecreates=not(args.nofilecreates),
                          plotfilemoves=not(args.nofilemoves),
                          plotfiledeletes=not(args.nofiledeletes),
                          plotfilecopies=not(args.nofilecopies),
                          plotfilereads=not(args.nofilereads),
                          plotfilewrites=not(args.nofilewrites),
                          plotregistry=not(args.noregistry),
                          plotregistrycreates=not(args.noregcreates),
                          plotregistrydeletes=not(args.noregdeletes),
                          plotregistrywrites=not(args.noregwrites),
                          plotregistryreads=not(args.noregreads),
                          ignorepaths=ignorepaths,
                          includepaths=includepaths)

    print('Plotting log: {0}'.format(jsonfile))
    vl.plotgraph(filename=filename, title=args.title,
                 graphvizprog=args.graphvizprog)


#
# Main function for plotprocmoncsv
#
def plotprocmoncsv():
    #
    # COMMAND LINE ARGS
    #

    # Setup command line argument parsing.
    parser = argparse.ArgumentParser(
        description='Application to graph ProcMon CSV files')

    parser.add_argument('ProcMonCSVFile',
                        help='ProcMon CSV file')

    parser.add_argument('-f',
                        '--file', metavar='HTMLFile',
                        default='procmoncsv.html',
                        help='Create the html report. Default name '
                        'is procmoncsv.html')

    parser.add_argument('-t',
                        '--title',
                        help='The title for the plot')

    parser.add_argument('-pa',
                        '--plotall', action='store_true',
                        help='Plot all aspects')

    parser.add_argument('-pf',
                        '--plotfile', action='store_true',
                        help='Plot all file aspects')

    parser.add_argument('-pu',
                        '--plotudp', action='store_true',
                        help='Plot all UDP aspects')

    parser.add_argument('-pt',
                        '--plottcp', action='store_true',
                        help='Plot all TCP aspects')

    parser.add_argument('-pr',
                        '--plotreg', action='store_true',
                        help='Plot all Registry aspects')

    parser.add_argument('-pfw',
                        '--plotfilewrites', action='store_true',
                        help='Plot file writes')

    parser.add_argument('-pfr',
                        '--plotfilereads', action='store_true',
                        help='Plot file reads')

    parser.add_argument('-pfd',
                        '--plotfiledeletes', action='store_true',
                        help='Plot file deletes')

    parser.add_argument('-pfn',
                        '--plotfilerenames', action='store_true',
                        help='Plot file renames')

    parser.add_argument('-ptcp',
                        '--plottcpconnects', action='store_true',
                        help='Plot TCP connects')

    parser.add_argument('-pus',
                        '--plotudpsends', action='store_true',
                        help='Plot UDP sends')

    parser.add_argument('-pur',
                        '--plotudprecvs', action='store_true',
                        help='Plot UDP receives')

    parser.add_argument('-prr',
                        '--plotregreads', action='store_true',
                        help='Plot Registry reads')

    parser.add_argument('-prw',
                        '--plotregwrites', action='store_true',
                        help='Plot Registry writes')

    parser.add_argument('-prd',
                        '--plotregdeletes', action='store_true',
                        help='Plot Registry deletes')

    parser.add_argument('-sa',
                        '--showalllabels', action='store_true',
                        help='Show all labels')

    parser.add_argument('-sp',
                        '--showproclabels', action='store_true',
                        help='Show process labels')

    parser.add_argument('-st',
                        '--showtcplabels', action='store_true',
                        help='Show TCP labels')

    parser.add_argument('-su',
                        '--showudplabels', action='store_true',
                        help='Show UDP labels')

    parser.add_argument('-sf',
                        '--showfilelabels', action='store_true',
                        help='Show file labels')

    parser.add_argument('-sh',
                        '--showhostlabels', action='store_true',
                        help='Show host labels')

    parser.add_argument('-sr',
                        '--showreglabels', action='store_true',
                        help='Show Registry labels')

    parser.add_argument('-ignpaths',
                        '--ignorepathsfile', metavar='IgnPathsFile.txt',
                        help='File containing regular expressions to ignore '
                        'in the Path column.  One RE per line.')

    parser.add_argument('-inclpaths',
                        '--includepathsfile', metavar='InclPathsFile.txt',
                        help='File containing regular expressions to include '
                        'in the Path column.  Overrides ignores. '
                        'One RE per line.')

    parser.add_argument('-gp',
                        '--graphvizprog', default='sfdp',
                        help='The graphviz layout program to use.  Valid '
                             'options are dot, neato, twopi, circo, fdp, '
                             'sfdp, patchwork and osage.  Research the '
                             'graphviz website for more information on '
                             'these types of layouts.  IF YOU SUPPLY AN '
                             'INVALID VALUE THIS PROGRAM WILL NOT WORK! '
                             'Default: sfdp')

    # Parse command line arguments.
    args = parser.parse_args()

    csvfile = args.ProcMonCSVFile
    filename = args.file

    if args.includepathsfile is not None:
        inclfile = args.includepathsfile
        if not os.path.exists(inclfile):
            print('Include file does not exist: {0}'.format(inclfile))
            exit(1)
        with open(inclfile) as infile:
            try:
                includepaths = infile.read().splitlines()
            except:
                print('ERROR:  File problem: {0}'.format(inclfile))
                exit(1)
    else:
        includepaths = None

    if args.ignorepathsfile is not None:
        ignfile = args.ignorepathsfile
        if not os.path.exists(ignfile):
            print('Ignore file does not exist: {0}'.format(ignfile))
            exit(1)
        with open(ignfile) as infile:
            try:
                ignorepaths = infile.read().splitlines()
            except:
                print('ERROR:  File problem: {0}'.format(ignfile))
                exit(1)
    else:
        ignorepaths = None

    showproclabels = args.showproclabels
    showtcplabels = args.showtcplabels
    showudplabels = args.showudplabels
    showfilelabels = args.showfilelabels
    showhostlabels = args.showhostlabels
    showreglabels = args.showreglabels
    plottcpconnects = args.plottcpconnects
    plotudpsends = args.plotudpsends
    plotudprecvs = args.plotudprecvs
    plotfilereads = args.plotfilereads
    plotfilewrites = args.plotfilewrites
    plotfiledeletes = args.plotfiledeletes
    plotfilerenames = args.plotfilerenames
    plotregreads = args.plotregreads
    plotregwrites = args.plotregwrites
    plotregdeletes = args.plotregdeletes

    if args.showalllabels is True:
        showproclabels = True
        showtcplabels = True
        showudplabels = True
        showfilelabels = True
        showhostlabels = True
        showreglabels = True

    if args.plotall is True:
        plottcpconnects = True
        plotudpsends = True
        plotudprecvs = True
        plotfilereads = True
        plotfilewrites = True
        plotfiledeletes = True
        plotfilerenames = True
        plotregreads = True
        plotregwrites = True
        plotregdeletes = True

    if args.plotfile is True:
        plotfilereads = True
        plotfilewrites = True
        plotfiledeletes = True

    if args.plottcp is True:
        plottcpconnects = True

    if args.plotudp is True:
        plotudpsends = True
        plotudprecvs = True

    if args.plotreg is True:
        plotregreads = True
        plotregwrites = True
        plotregdeletes = True

    if not os.path.exists(csvfile):
        print('File does not exist: {0}'.format(csvfile))
        exit(1)

    print('Reading log: {0}'.format(csvfile))
    vl = ProcMonCSV(csvfile)

    print('Plotting log: {0}'.format(csvfile))
    vl.plotgraph(
        showproclabels=showproclabels,
        showtcplabels=showtcplabels,
        showudplabels=showudplabels,
        showfilelabels=showfilelabels,
        showhostlabels=showhostlabels,
        showreglabels=showreglabels,
        plottcpconnects=plottcpconnects,
        plotudpsends=plotudpsends,
        plotudprecvs=plotudprecvs,
        plotfilereads=plotfilereads,
        plotfilewrites=plotfilewrites,
        plotfiledeletes=plotfiledeletes,
        plotfilerenames=plotfilerenames,
        plotregreads=plotregreads,
        plotregwrites=plotregwrites,
        plotregdeletes=plotregdeletes,
        ignorepaths=ignorepaths,
        includepaths=includepaths,
        filename=filename,
        title=args.title,
        graphvizprog=args.graphvizprog
        )
