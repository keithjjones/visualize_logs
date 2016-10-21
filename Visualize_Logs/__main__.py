#
# INCLUDES
#

# Required for complex command line argument parsing.
import argparse
# For paths
import os
# Required for plotting logs
import Visualize_Logs


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
                        help='Create the log file.')

    parser.add_argument('-pa',
                        '--plotall', action='store_true',
                        help='Plot all aspects')

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

    parser.add_argument('-pt',
                        '--plottcpconnects', action='store_true',
                        help='Plot TCP connects')

    parser.add_argument('-pus',
                        '--plotudpsends', action='store_true',
                        help='Plot UDP sends')

    parser.add_argument('-pur',
                        '--plotudprecvs', action='store_true',
                        help='Plot UDP receives')

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

    # Parse command line arguments.
    args = parser.parse_args()

    csvfile = args.ProcMonCSVFile
    filename = args.file

    if args.showalllabels is True:
        showproclabels = True
        showtcplabels = True
        showudplabels = True
        showfilelabels = True
        showhostlabels = True
    else:
        showproclabels = args.showproclabels
        showtcplabels = args.showtcplabels
        showudplabels = args.showudplabels
        showfilelabels = args.showfilelabels
        showhostlabels = args.showhostlabels

    if args.plotall is True:
        plottcpconnects = True
        plotudpsends = True
        plotudprecvs = True
        plotfilereads = True
        plotfilewrites = True
        plotfiledeletes = True
        plotfilerenames = True
    else:
        plottcpconnects = args.plottcpconnects
        plotudpsends = args.plotudpsends
        plotudprecvs = args.plotudprecvs
        plotfilereads = args.plotfilereads
        plotfilewrites = args.plotfilewrites
        plotfiledeletes = args.plotfiledeletes
        plotfilerenames = args.plotfilerenames

    if not os.path.exists(csvfile):
        print('File does not exist: {0}'.format(csvfile))
        exit(1)

    print('Reading log: {0}'.format(csvfile))
    vl = Visualize_Logs.ProcMonCSV(csvfile)

    print('Plotting log: {0}'.format(csvfile))
    vl.plotgraph(
        showproclabels=showproclabels,
        showtcplabels=showtcplabels,
        showudplabels=showudplabels,
        showfilelabels=showfilelabels,
        showhostlabels=showhostlabels,
        plottcpconnects=plottcpconnects,
        plotudpsends=plotudpsends,
        plotudprecvs=plotudprecvs,
        plotfilereads=plotfilereads,
        plotfilewrites=plotfilewrites,
        plotfiledeletes=plotfiledeletes,
        plotfilerenames=plotfilerenames,
        filename=filename
        )
