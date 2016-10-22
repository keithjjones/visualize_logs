#
# Includes
#

# NetworkX
import networkx

# Pandas
import pandas

# OS
import os

# Plotly
from plotly.offline import plot
from plotly.graph_objs import Bar, Scatter, Figure, Layout, \
    Line, Marker, Annotations, Annotation, XAxis, YAxis

# Regular Expressions
import re


#
# Classes
#

class ProcMonCSV(object):
    """
    Class to hold ProcMon CSV logs.

    https://technet.microsoft.com/en-us/sysinternals/processmonitor.aspx

    """

    ignorepaths = []
    """List of regular expressions to ignore in Path column."""

    includepaths = []
    """List of regular expressions to include in Path column."""

    def __init__(self, csvlogfile=None):
        """
        The CSV file is read and parsed using this Class.  This could
        take a while depending on how big your ProcMon CSV file is.

        This class REQUIRES the following fields in the ProcMon CSV:

        Time of Day
        Date & Time
        Process Name
        PID
        Operation
        Path
        Result
        Detail
        TID
        Duration
        Image Path
        Command Line
        Parent PID
        Event Class
        User
        Session
        Category
        Architecture


        :param csvlogfile: A CSV log file from ProcMon
        :type csvlogfile: A string
        :returns: An object
        :rtype: ProcMonCSV object

        """
        if not os.path.exists(csvlogfile):
            raise VisualizeLogsInvalidFile(csvlogfile)
        else:
            self.csvlogfile = csvlogfile

        try:
            self.csvdata = pandas.read_csv(csvlogfile, low_memory=False)
        except:
            raise VisualizeLogsInvalidFileStructure(csvlogfile)

        # Check existence of fields...
        if 'Date & Time' not in self.csvdata:
            raise VisualizeLogsMissingRequiredField(self.csvlogfile,
                                                    'Date & Time')
        if 'Time of Day' not in self.csvdata:
            raise VisualizeLogsMissingRequiredField(self.csvlogfile,
                                                    'Time of Day')
        if 'Process Name' not in self.csvdata:
            raise VisualizeLogsMissingRequiredField(self.csvlogfile,
                                                    'Process Name')
        if 'PID' not in self.csvdata:
            raise VisualizeLogsMissingRequiredField(self.csvlogfile,
                                                    'PID')
        if 'Operation' not in self.csvdata:
            raise VisualizeLogsMissingRequiredField(self.csvlogfile,
                                                    'Operation')
        if 'Path' not in self.csvdata:
            raise VisualizeLogsMissingRequiredField(self.csvlogfile,
                                                    'Path')
        if 'Result' not in self.csvdata:
            raise VisualizeLogsMissingRequiredField(self.csvlogfile,
                                                    'Result')
        if 'Detail' not in self.csvdata:
            raise VisualizeLogsMissingRequiredField(self.csvlogfile,
                                                    'Detail')
        if 'TID' not in self.csvdata:
            raise VisualizeLogsMissingRequiredField(self.csvlogfile,
                                                    'TID')
        if 'Duration' not in self.csvdata:
            raise VisualizeLogsMissingRequiredField(self.csvlogfile,
                                                    'Duration')
        if 'Image Path' not in self.csvdata:
            raise VisualizeLogsMissingRequiredField(self.csvlogfile,
                                                    'Image Path')
        if 'Command Line' not in self.csvdata:
            raise VisualizeLogsMissingRequiredField(self.csvlogfile,
                                                    'Command Line')
        if 'Parent PID' not in self.csvdata:
            raise VisualizeLogsMissingRequiredField(self.csvlogfile,
                                                    'Parent PID')
        if 'Event Class' not in self.csvdata:
            raise VisualizeLogsMissingRequiredField(self.csvlogfile,
                                                    'Event Class')
        if 'User' not in self.csvdata:
            raise VisualizeLogsMissingRequiredField(self.csvlogfile,
                                                    'User')
        if 'Session' not in self.csvdata:
            raise VisualizeLogsMissingRequiredField(self.csvlogfile,
                                                    'Session')
        if 'Category' not in self.csvdata:
            raise VisualizeLogsMissingRequiredField(self.csvlogfile,
                                                    'Category')
        if 'Architecture' not in self.csvdata:
            raise VisualizeLogsMissingRequiredField(self.csvlogfile,
                                                    'Architecture')

        # Convert Date and Time...
        if 'Date & Time' in self.csvdata:
            self.csvdata['Date & Time'] = pandas.to_datetime(
                self.csvdata['Date & Time'])

        # # Convert Time of Day
        # if 'Time of Day' in self.csvdata:
        #     self.csvdata['Time of Day'] = pandas.to_datetime(
        #         self.csvdata['Time of Day']).dt.time

        # Construct real time...
        self.csvdata['Time'] = pandas.to_datetime(
            self.csvdata['Date & Time'].dt.date.map(str) + " " +
            self.csvdata['Time of Day']
            )

        # Be sure the data is sorted by time then by PID
        sortedcsvdata = self.csvdata.sort_values(['Time', 'PID'])
        self.csvdata = sortedcsvdata

    def _addnodemetadata(self, i, node):
        """

        Internal function to add node metadata for graphed nodes.

        :param i: The index of the row from the ProcMon CSV data
        :param node:  The row of the ProcMon CSV data from itterrow
        :returns: Nothing

        """
        self.nodemetadata[i] = dict({
            'PID': node['PID'],
            'Time': node['Time'],
            'Process Name': node['Process Name'],
            'Operation': node['Operation'],
            'Path': node['Path'],
            'Result': node['Result'],
            'Detail': node['Detail'],
            'TID': node['TID'],
            'Duration': node['Duration'],
            'Image Path': node['Image Path'],
            'Command Line': node['Command Line'],
            'Parent PID': node['Parent PID'],
            'Event Class': node['Event Class'],
            'User': node['User'],
            'Session': node['Session'],
            'Category': node['Category'],
            'Architecture': node['Architecture']
             })

    def _addunknownpid(self, unkpid, row=None):
        """

        Internal function to create an unknown pid.

        :returns: Node name

        """
        nodename = "* UNKNOWN PID {0}".format(unkpid)
        if nodename not in self.digraph:
            self.digraph.add_node(nodename,
                                  type='Unknown PID',
                                  pid=unkpid)

        if row is not None:
            self.unkpidcmdline[nodename] = [row['Image Path'],
                                            row['Command Line']]

        return nodename

    def _addedgetounknownpid(self, unkpid, idx, row=None):
        """

        Internal function to link an idx from an unknown pid.

        """
        nodename = self._addunknownpid(unkpid, row)
        if not self.digraph.has_edge(nodename, idx):
            self.digraph.add_edge(nodename, idx)

    def _addedgetohost(self, idx, host):
        """

        Internal function to link an idx to a host.

        """
        hostname = "\"* Host " + host + "\""
        if hostname not in self.digraph:
            self.digraph.add_node(hostname,
                                  type='host',
                                  host="\""+host+"\"")
        if not self.digraph.has_edge(idx, hostname):
            self.digraph.add_edge(idx,
                                  hostname)

    def _addfile(self, file):
        """

        Internal function to create a file.

        :returns: filename for the node

        """
        if file in self.filetable:
            filenum = self.filetable[file]
        else:
            filenum = len(self.filetable)
            self.filetable[file] = filenum

        filename = "\"* File {0}\"".format(filenum)

        if filename not in self.digraph:
            self.digraph.add_node(filename,
                                  type='file',
                                  filenum=filenum)
        return filename

    def _addedgetofiles(self, file1, file2):
        """

        Internal function to link 2 files.

        """
        filename1 = self._addfile(file1)
        filename2 = self._addfile(file2)

        if not self.digraph.has_edge(filename1, filename2):
            self.digraph.add_edge(filename1, filename2)

    def _addedgetofile(self, idx, file):
        """

        Internal function to link an idx to a file.

        """
        filename = self._addfile(file)

        if not self.digraph.has_edge(idx, filename):
            self.digraph.add_edge(idx,
                                  filename)

    def _addreg(self, reg):
        """

        Internal function to create a registry.

        :returns: filename for the node

        """
        if reg in self.regtable:
            regnum = self.regtable[reg]
        else:
            regnum = len(self.regtable)
            self.regtable[reg] = regnum

        regname = "\"* Reg {0}\"".format(regnum)

        if regname not in self.digraph:
            self.digraph.add_node(regname,
                                  type='reg',
                                  regnum=regnum)
        return regname

    def _addedgetoreg(self, idx, reg):
        """

        Internal function to link an idx to a registry.

        """
        regname = self._addreg(reg)

        if not self.digraph.has_edge(idx, regname):
            self.digraph.add_edge(idx,
                                  regname)

    def _plotevent(self, row):
        """

        Internal function to check if the event should be plotted.

        :returns:  True if the event should be plotted, False
            otherwise.

        """
        PlotEvent = True

        if not pandas.isnull(row['Path']):
            for r in self.ignorepaths:
                # In case the double escape is needed...
                # r = r.replace('\\', '\\\\')
                m = re.search(r, row['Path'], re.IGNORECASE)
                if m:
                    PlotEvent = False
                    break

            if PlotEvent is False:
                # In case the double escape is needed...
                # r = r.replace('\\', '\\\\')
                for r in self.includepaths:
                    m = re.search(r, row['Path'], re.IGNORECASE)
                    if m:
                        PlotEvent = True
                        break

        return PlotEvent

    def _constructgraph(self):
        """

        Internal function to construct the graph of ProcMon CSV data.

        :returns:  The output data for plotly.

        """
        # Create a dict to hold our currently running processes...
        currentprocs = dict()

        # Use this to get information for unknown pids...
        self.unkpidcmdline = dict()

        # Create dicts for file information so long paths
        # not sent to graphviz and such...
        self.filewritetable = dict()
        self.filereadtable = dict()
        self.filedeletetable = dict()
        self.filerenametable = dict()
        self.filetable = dict()

        # Create dicts for file information so long paths
        # not sent to graphviz and such...
        self.regwritetable = dict()
        self.regreadtable = dict()
        self.regdeletetable = dict()
        self.regtable = dict()

        # Create a structure to hold metadata about our nodes...
        self.nodemetadata = dict()

        # Create a network graph...
        self.digraph = networkx.DiGraph()

        # Crawl the CSV data...
        for i, row in self.csvdata.iterrows():
            # Skip this if not plotting event...
            if self._plotevent(row) is False:
                continue

            # Process Start...
            if row['Operation'] == 'Process Start':
                self.digraph.add_node(i, type='Process Start')
                self._addnodemetadata(i, row)
                # Set the current PID to this row, PIDs can be
                # reused...
                currentprocs[row['PID']] = i
                if row['Parent PID'] not in currentprocs:
                    self._addedgetounknownpid(row['Parent PID'], i)
                else:
                    self.digraph.add_edge(currentprocs[row['Parent PID']], i)

                # Link up new processes to files that may have been
                # messed with...
                if row['Image Path'] in self.filetable:
                    self._addedgetofile(i, row['Image Path'])

            if (row['Operation'] == 'TCP Connect' and
                    self.plottcpconnects is True):
                self.digraph.add_node(i, type='TCP Connect')
                self._addnodemetadata(i, row)
                if row['PID'] not in currentprocs:
                    self._addedgetounknownpid(row['PID'], i, row)
                else:
                    self.digraph.add_edge(currentprocs[row['PID']], i)
                m = re.search("\S+ -> (\S+):([^:]+)", row['Path'])
                if m:
                    host = m.group(1)
                    self._addedgetohost(i, host)
                else:
                    raise VisualizeLogsParseError(row['Path'])
            if (row['Operation'] == 'UDP Receive' and
                    self.plotudprecvs is True):
                self.digraph.add_node(i, type='UDP Receive')
                self._addnodemetadata(i, row)
                if row['PID'] not in currentprocs:
                    self._addedgetounknownpid(row['PID'], i, row)
                else:
                    self.digraph.add_edge(currentprocs[row['PID']], i)
                m = re.search("\S+ -> (\S+):([^:]+)", row['Path'])
                if m:
                    host = m.group(1)
                    self._addedgetohost(i, host)
                else:
                    raise VisualizeLogsParseError(row['Path'])
            if (row['Operation'] == 'UDP Send' and
                    self.plotudpsends is True):
                self.digraph.add_node(i, type='UDP Send')
                self._addnodemetadata(i, row)
                if row['PID'] not in currentprocs:
                    self._addedgetounknownpid(row['PID'], i, row)
                else:
                    self.digraph.add_edge(currentprocs[row['PID']], i)
                m = re.search("\S+ -> (\S+):([^:]+)", row['Path'])
                if m:
                    host = m.group(1)
                    self._addedgetohost(i, host)
                else:
                    raise VisualizeLogsParseError(row['Path'])
            if (row['Operation'] == 'WriteFile' and
                    self.plotfilewrites is True):
                if row['PID'] not in currentprocs:
                    pidnode = self._addunknownpid(row['PID'], row)
                else:
                    pidnode = currentprocs[row['PID']]

                nodename = ("\"* PID {0} Writes File {1}\""
                            .format(pidnode, row['Path']))

                if nodename not in self.filewritetable:
                    nextnum = len(self.filewritetable)
                    realnodename = '\"* File Write {0}\"'.format(nextnum)
                    self.filewritetable[nodename] = realnodename
                    self.digraph.add_node(realnodename, type='WriteFile')
                else:
                    realnodename = self.filewritetable[nodename]

                if row['PID'] not in currentprocs:
                    self._addedgetounknownpid(row['PID'], realnodename, row)
                elif not self.digraph.has_edge(currentprocs[row['PID']],
                                               realnodename):
                    self.digraph.add_edge(currentprocs[row['PID']],
                                          realnodename)

                self._addedgetofile(realnodename, row['Path'])
            if (row['Operation'] == 'ReadFile' and
                    self.plotfilereads is True):
                if row['PID'] not in currentprocs:
                    pidnode = self._addunknownpid(row['PID'], row)
                else:
                    pidnode = currentprocs[row['PID']]

                nodename = ("\"* PID {0} Reads File {1}\""
                            .format(pidnode, row['Path']))

                if nodename not in self.filereadtable:
                    nextnum = len(self.filereadtable)
                    realnodename = '\"* File Read {0}\"'.format(nextnum)
                    self.filereadtable[nodename] = realnodename
                    self.digraph.add_node(realnodename, type='ReadFile')
                else:
                    realnodename = self.filereadtable[nodename]

                if row['PID'] not in currentprocs:
                    self._addedgetounknownpid(row['PID'], realnodename, row)
                elif not self.digraph.has_edge(currentprocs[row['PID']],
                                               realnodename):
                    self.digraph.add_edge(currentprocs[row['PID']],
                                          realnodename)

                self._addedgetofile(realnodename, row['Path'])
            if (row['Operation'] == 'SetDispositionInformationFile' and
                    self.plotfiledeletes is True):
                if row['PID'] not in currentprocs:
                    pidnode = self._addunknownpid(row['PID'], row)
                else:
                    pidnode = currentprocs[row['PID']]

                nodename = ("\"* PID {0} Deletes File {1}\""
                            .format(pidnode, row['Path']))

                if nodename not in self.filedeletetable:
                    nextnum = len(self.filedeletetable)
                    realnodename = '\"* File Delete {0}\"'.format(nextnum)
                    self.filedeletetable[nodename] = realnodename
                    self.digraph.add_node(realnodename,
                                          type='SetDispositionInformationFile')
                else:
                    realnodename = self.filedeletetable[nodename]

                if row['PID'] not in currentprocs:
                    self._addedgetounknownpid(row['PID'], realnodename, row)
                elif not self.digraph.has_edge(currentprocs[row['PID']],
                                               realnodename):
                    self.digraph.add_edge(currentprocs[row['PID']],
                                          realnodename)

                self._addedgetofile(realnodename, row['Path'])
            if (row['Operation'] == 'SetRenameInformationFile' and
                    self.plotfilerenames is True):
                if row['PID'] not in currentprocs:
                    pidnode = self._addunknownpid(row['PID'], row)
                else:
                    pidnode = currentprocs[row['PID']]

                m = re.search(".* FileName: (.*)$", row['Detail'])
                if m:
                    destfile = m.group(1)
                else:
                    raise VisualizeLogsParseError(row['Details'])

                nodename = ("\"* PID {0} Renames File {1} to {2}\""
                            .format(pidnode, row['Path'], destfile))

                if nodename not in self.filerenametable:
                    nextnum = len(self.filerenametable)
                    realnodename = '\"* File Rename {0}\"'.format(nextnum)
                    self.filerenametable[nodename] = realnodename
                    self.digraph.add_node(realnodename,
                                          type='SetRenameInformationFile')
                else:
                    realnodename = self.filerenametable[nodename]

                if row['PID'] not in currentprocs:
                    self._addedgetounknownpid(row['PID'], realnodename, row)
                elif not self.digraph.has_edge(currentprocs[row['PID']],
                                               realnodename):
                    self.digraph.add_edge(currentprocs[row['PID']],
                                          realnodename)

                self._addedgetofile(realnodename, row['Path'])

                self._addedgetofiles(row['Path'], destfile)
            if (row['Operation'] == 'RegSetValue' and
                    self.plotregwrites is True):
                if row['PID'] not in currentprocs:
                    pidnode = self._addunknownpid(row['PID'], row)
                else:
                    pidnode = currentprocs[row['PID']]

                nodename = ("\"* PID {0} Writes Reg {1}\""
                            .format(pidnode, row['Path']))

                if nodename not in self.regwritetable:
                    nextnum = len(self.regwritetable)
                    realnodename = '\"* Reg Write {0}\"'.format(nextnum)
                    self.regwritetable[nodename] = realnodename
                    self.digraph.add_node(realnodename, type='RegSetValue')
                else:
                    realnodename = self.regwritetable[nodename]

                if row['PID'] not in currentprocs:
                    self._addedgetounknownpid(row['PID'], realnodename, row)
                elif not self.digraph.has_edge(currentprocs[row['PID']],
                                               realnodename):
                    self.digraph.add_edge(currentprocs[row['PID']],
                                          realnodename)

                self._addedgetoreg(realnodename, row['Path'])
            if (row['Operation'] == 'RegQueryValue' and
                    self.plotregreads is True):
                if row['PID'] not in currentprocs:
                    pidnode = self._addunknownpid(row['PID'], row)
                else:
                    pidnode = currentprocs[row['PID']]

                nodename = ("\"* PID {0} Reads Reg {1}\""
                            .format(pidnode, row['Path']))

                if nodename not in self.regreadtable:
                    nextnum = len(self.regreadtable)
                    realnodename = '\"* Reg Read {0}\"'.format(nextnum)
                    self.regreadtable[nodename] = realnodename
                    self.digraph.add_node(realnodename, type='RegQueryValue')
                else:
                    realnodename = self.regreadtable[nodename]

                if row['PID'] not in currentprocs:
                    self._addedgetounknownpid(row['PID'], realnodename, row)
                elif not self.digraph.has_edge(currentprocs[row['PID']],
                                               realnodename):
                    self.digraph.add_edge(currentprocs[row['PID']],
                                          realnodename)

                self._addedgetoreg(realnodename, row['Path'])
            if (row['Operation'] == 'RegDeleteValue' and
                    self.plotregdeletes is True):
                if row['PID'] not in currentprocs:
                    pidnode = self._addunknownpid(row['PID'], row)
                else:
                    pidnode = currentprocs[row['PID']]

                nodename = ("\"* PID {0} Deletes Reg {1}\""
                            .format(pidnode, row['Path']))

                if nodename not in self.regdeletetable:
                    nextnum = len(self.regdeletetable)
                    realnodename = '\"* Reg Delete {0}\"'.format(nextnum)
                    self.regdeletetable[nodename] = realnodename
                    self.digraph.add_node(realnodename, type='RegDeleteValue')
                else:
                    realnodename = self.regdeletetable[nodename]

                if row['PID'] not in currentprocs:
                    self._addedgetounknownpid(row['PID'], realnodename, row)
                elif not self.digraph.has_edge(currentprocs[row['PID']],
                                               realnodename):
                    self.digraph.add_edge(currentprocs[row['PID']],
                                          realnodename)

                self._addedgetoreg(realnodename, row['Path'])

        # Create the positions...
        if self.graphvizprog is None:
            #  self.pos = networkx.fruchterman_reingold_layout(self.digraph)
            self.pos = networkx.spring_layout(self.digraph)
            # self.pos = networkx.circular_layout(self.digraph)
            # self.pos = networkx.shell_layout(self.digraph)
            # self.pos = networkx.spectral_layout(self.digraph)
        else:
            self.pos = \
                networkx.drawing.nx_pydot.graphviz_layout(self.digraph,
                                                          prog=self.graphvizprog)

        return self._generateplot()

    def _generateplot(self):
        """

        Internal function to generate the Scatter plots.

        :returns:  The output data for plotly.

        """

        # Used this methodology...
        # https://plot.ly/python/igraph-networkx-comparison/

        # Node coordinates...
        ProcessX = []
        ProcessY = []
        TCPConnectX = []
        TCPConnectY = []
        UDPReceiveX = []
        UDPReceiveY = []
        UDPSendX = []
        UDPSendY = []
        HostX = []
        HostY = []
        FileWriteX = []
        FileWriteY = []
        FileReadX = []
        FileReadY = []
        FileDeleteX = []
        FileDeleteY = []
        FileRenameX = []
        FileRenameY = []
        FileX = []
        FileY = []
        RegWriteX = []
        RegWriteY = []
        RegReadX = []
        RegReadY = []
        RegDeleteX = []
        RegDeleteY = []
        RegX = []
        RegY = []

        # Edge coordinates...
        ProcessXe = []
        ProcessYe = []
        TCPConnectXe = []
        TCPConnectYe = []
        UDPReceiveXe = []
        UDPReceiveYe = []
        UDPSendXe = []
        UDPSendYe = []
        FileWriteXe = []
        FileWriteYe = []
        FileReadXe = []
        FileReadYe = []
        FileDeleteXe = []
        FileDeleteYe = []
        FileImageXe = []
        FileImageYe = []
        FileRenameXe = []
        FileRenameYe = []
        FileRenamedXe = []
        FileRenamedYe = []
        RegWriteXe = []
        RegWriteYe = []
        RegReadXe = []
        RegReadYe = []
        RegDeleteXe = []
        RegDeleteYe = []

        # Hover Text...
        proctxt = []
        tcpconntxt = []
        udprectxt = []
        udpsendtxt = []
        hosttxt = []
        filewritetxt = []
        filereadtxt = []
        filedeletetxt = []
        filerenametxt = []
        filetxt = []
        regwritetxt = []
        regreadtxt = []
        regdeletetxt = []
        regtxt = []

        # Get the node positions...
        for node in self.digraph:
            if self.digraph.node[node]['type'] == 'Process Start':
                ProcessX.append(self.pos[node][0])
                ProcessY.append(self.pos[node][1])
                proctxt.append(
                    "PID: {0}<br>"
                    "Command: {1}<br>"
                    "Time: {2}<br>"
                    "User: {3}<br>"
                    "Architecture: {4}<br>"
                    "Parent PID: {5}"
                    .format(
                        self.nodemetadata[node]['PID'],
                        self.nodemetadata[node]['Command Line'],
                        self.nodemetadata[node]['Time'],
                        self.nodemetadata[node]['User'],
                        self.nodemetadata[node]['Architecture'],
                        self.nodemetadata[node]['Parent PID']
                        )
                               )
            if self.digraph.node[node]['type'] == 'Unknown PID':
                ProcessX.append(self.pos[node][0])
                ProcessY.append(self.pos[node][1])
                if node not in self.unkpidcmdline:
                    proctxt.append(
                        "Unknown PID: {0}"
                        .format(self.digraph.node[node]['pid'])
                                   )
                else:
                    proctxt.append(
                        "Unknown PID: {0}<br>"
                        "Image Path: {1}<br>"
                        "Command Line: {2}"
                        .format(self.digraph.node[node]['pid'],
                                self.unkpidcmdline[node][0],
                                self.unkpidcmdline[node][1])
                                   )
            if self.digraph.node[node]['type'] == 'TCP Connect':
                TCPConnectX.append(self.pos[node][0])
                TCPConnectY.append(self.pos[node][1])
                tcpconntxt.append(
                    "Time: {0}<br>"
                    "Path: {1}<br>"
                    "PID: {2}<br>"
                    "Command: {3}<br>"
                    "User: {4}<br>"
                    "Architecture: {5}<br>"
                    .format(
                        self.nodemetadata[node]['Time'],
                        self.nodemetadata[node]['Path'],
                        self.nodemetadata[node]['PID'],
                        self.nodemetadata[node]['Command Line'],
                        self.nodemetadata[node]['User'],
                        self.nodemetadata[node]['Architecture']
                        )
                               )
            if self.digraph.node[node]['type'] == 'UDP Receive':
                UDPReceiveX.append(self.pos[node][0])
                UDPReceiveY.append(self.pos[node][1])
                udprectxt.append(
                    "Time: {0}<br>"
                    "Path: {1}<br>"
                    "PID: {2}<br>"
                    "Command: {3}<br>"
                    "User: {4}<br>"
                    "Architecture: {5}<br>"
                    .format(
                        self.nodemetadata[node]['Time'],
                        self.nodemetadata[node]['Path'],
                        self.nodemetadata[node]['PID'],
                        self.nodemetadata[node]['Command Line'],
                        self.nodemetadata[node]['User'],
                        self.nodemetadata[node]['Architecture']
                        )
                               )
            if self.digraph.node[node]['type'] == 'UDP Send':
                UDPSendX.append(self.pos[node][0])
                UDPSendY.append(self.pos[node][1])
                udpsendtxt.append(
                    "Time: {0}<br>"
                    "Path: {1}<br>"
                    "PID: {2}<br>"
                    "Command: {3}<br>"
                    "User: {4}<br>"
                    "Architecture: {5}<br>"
                    .format(
                        self.nodemetadata[node]['Time'],
                        self.nodemetadata[node]['Path'],
                        self.nodemetadata[node]['PID'],
                        self.nodemetadata[node]['Command Line'],
                        self.nodemetadata[node]['User'],
                        self.nodemetadata[node]['Architecture']
                        )
                               )
            if self.digraph.node[node]['type'] == 'host':
                HostX.append(self.pos[node][0])
                HostY.append(self.pos[node][1])
                hosttxt.append(
                    "{0}"
                    .format(
                        self.digraph.node[node]['host'][1:-1]
                        )
                               )
            if self.digraph.node[node]['type'] == 'WriteFile':
                FileWriteX.append(self.pos[node][0])
                FileWriteY.append(self.pos[node][1])
                filewritetxt.append("WRITE")
            if self.digraph.node[node]['type'] == 'ReadFile':
                FileReadX.append(self.pos[node][0])
                FileReadY.append(self.pos[node][1])
                filereadtxt.append("READ")
            if (self.digraph.node[node]['type']
                    == 'SetDispositionInformationFile'):
                FileDeleteX.append(self.pos[node][0])
                FileDeleteY.append(self.pos[node][1])
                filedeletetxt.append("DELETE")
            if (self.digraph.node[node]['type']
                    == 'SetRenameInformationFile'):
                FileRenameX.append(self.pos[node][0])
                FileRenameY.append(self.pos[node][1])
                filerenametxt.append("RENAME")
            if self.digraph.node[node]['type'] == 'file':
                FileX.append(self.pos[node][0])
                FileY.append(self.pos[node][1])

                for f in self.filetable:
                    if self.filetable[f] == self.digraph.node[node]['filenum']:
                        filename = f
                        break
                filetxt.append("{0}".format(filename))
            if self.digraph.node[node]['type'] == 'RegSetValue':
                RegWriteX.append(self.pos[node][0])
                RegWriteY.append(self.pos[node][1])
                regwritetxt.append("WRITE")
            if self.digraph.node[node]['type'] == 'RegQueryValue':
                RegReadX.append(self.pos[node][0])
                RegReadY.append(self.pos[node][1])
                regreadtxt.append("READ")
            if (self.digraph.node[node]['type'] == 'RegDeleteValue'):
                RegDeleteX.append(self.pos[node][0])
                RegDeleteY.append(self.pos[node][1])
                regdeletetxt.append("DELETE")
            if self.digraph.node[node]['type'] == 'reg':
                RegX.append(self.pos[node][0])
                RegY.append(self.pos[node][1])

                for r in self.regtable:
                    if self.regtable[r] == self.digraph.node[node]['regnum']:
                        regname = r
                        break
                regtxt.append("{0}".format(regname))

        # Get edge positions...
        for edge in self.digraph.edges():
            if (self.digraph.node[edge[1]]['type'] == 'Process Start' or
                    self.digraph.node[edge[1]]['type'] == 'Unknown PID'):
                ProcessXe.append(self.pos[edge[0]][0])
                ProcessXe.append(self.pos[edge[1]][0])
                ProcessXe.append(None)
                ProcessYe.append(self.pos[edge[0]][1])
                ProcessYe.append(self.pos[edge[1]][1])
                ProcessYe.append(None)
            if (self.digraph.node[edge[1]]['type'] == 'TCP Connect' or
                    self.digraph.node[edge[0]]['type'] == 'TCP Connect'):
                TCPConnectXe.append(self.pos[edge[0]][0])
                TCPConnectXe.append(self.pos[edge[1]][0])
                TCPConnectXe.append(None)
                TCPConnectYe.append(self.pos[edge[0]][1])
                TCPConnectYe.append(self.pos[edge[1]][1])
                TCPConnectYe.append(None)
            if (self.digraph.node[edge[1]]['type'] == 'UDP Receive' or
                    self.digraph.node[edge[0]]['type'] == 'UDP Receive'):
                UDPReceiveXe.append(self.pos[edge[0]][0])
                UDPReceiveXe.append(self.pos[edge[1]][0])
                UDPReceiveXe.append(None)
                UDPReceiveYe.append(self.pos[edge[0]][1])
                UDPReceiveYe.append(self.pos[edge[1]][1])
                UDPReceiveYe.append(None)
            if (self.digraph.node[edge[1]]['type'] == 'UDP Send' or
                    self.digraph.node[edge[0]]['type'] == 'UDP Send'):
                UDPSendXe.append(self.pos[edge[0]][0])
                UDPSendXe.append(self.pos[edge[1]][0])
                UDPSendXe.append(None)
                UDPSendYe.append(self.pos[edge[0]][1])
                UDPSendYe.append(self.pos[edge[1]][1])
                UDPSendYe.append(None)
            if (self.digraph.node[edge[1]]['type'] == 'WriteFile' or
                    self.digraph.node[edge[0]]['type'] == 'WriteFile'):
                FileWriteXe.append(self.pos[edge[0]][0])
                FileWriteXe.append(self.pos[edge[1]][0])
                FileWriteXe.append(None)
                FileWriteYe.append(self.pos[edge[0]][1])
                FileWriteYe.append(self.pos[edge[1]][1])
                FileWriteYe.append(None)
            if (self.digraph.node[edge[1]]['type'] == 'ReadFile' or
                    self.digraph.node[edge[0]]['type'] == 'ReadFile'):
                FileReadXe.append(self.pos[edge[0]][0])
                FileReadXe.append(self.pos[edge[1]][0])
                FileReadXe.append(None)
                FileReadYe.append(self.pos[edge[0]][1])
                FileReadYe.append(self.pos[edge[1]][1])
                FileReadYe.append(None)
            if (self.digraph.node[edge[1]]['type']
                == 'SetDispositionInformationFile' or
                self.digraph.node[edge[0]]['type']
                    == 'SetDispositionInformationFile'):
                FileDeleteXe.append(self.pos[edge[0]][0])
                FileDeleteXe.append(self.pos[edge[1]][0])
                FileDeleteXe.append(None)
                FileDeleteYe.append(self.pos[edge[0]][1])
                FileDeleteYe.append(self.pos[edge[1]][1])
                FileDeleteYe.append(None)
            if (self.digraph.node[edge[0]]['type']
                == 'SetRenameInformationFile' or
                self.digraph.node[edge[1]]['type']
                    == 'SetRenameInformationFile'):
                FileRenameXe.append(self.pos[edge[0]][0])
                FileRenameXe.append(self.pos[edge[1]][0])
                FileRenameXe.append(None)
                FileRenameYe.append(self.pos[edge[0]][1])
                FileRenameYe.append(self.pos[edge[1]][1])
                FileRenameYe.append(None)
            if (self.digraph.node[edge[0]]['type']
                == 'file' and
                self.digraph.node[edge[1]]['type']
                    == 'file'):
                FileRenamedXe.append(self.pos[edge[0]][0])
                FileRenamedXe.append(self.pos[edge[1]][0])
                FileRenamedXe.append(None)
                FileRenamedYe.append(self.pos[edge[0]][1])
                FileRenamedYe.append(self.pos[edge[1]][1])
                FileRenamedYe.append(None)
            if ((self.digraph.node[edge[1]]['type'] == 'Process Start' and
                    self.digraph.node[edge[0]]['type'] == 'file') or
                    (self.digraph.node[edge[1]]['type'] == 'file' and
                     self.digraph.node[edge[0]]['type'] == 'Process Start')):
                FileImageXe.append(self.pos[edge[0]][0])
                FileImageXe.append(self.pos[edge[1]][0])
                FileImageXe.append(None)
                FileImageYe.append(self.pos[edge[0]][1])
                FileImageYe.append(self.pos[edge[1]][1])
                FileImageYe.append(None)
            if (self.digraph.node[edge[1]]['type'] == 'RegSetValue' or
                    self.digraph.node[edge[0]]['type'] == 'RegSetValue'):
                RegWriteXe.append(self.pos[edge[0]][0])
                RegWriteXe.append(self.pos[edge[1]][0])
                RegWriteXe.append(None)
                RegWriteYe.append(self.pos[edge[0]][1])
                RegWriteYe.append(self.pos[edge[1]][1])
                RegWriteYe.append(None)
            if (self.digraph.node[edge[1]]['type'] == 'RegQueryValue' or
                    self.digraph.node[edge[0]]['type'] == 'RegQueryValue'):
                RegReadXe.append(self.pos[edge[0]][0])
                RegReadXe.append(self.pos[edge[1]][0])
                RegReadXe.append(None)
                RegReadYe.append(self.pos[edge[0]][1])
                RegReadYe.append(self.pos[edge[1]][1])
                RegReadYe.append(None)
            if (self.digraph.node[edge[1]]['type'] == 'RegDeleteValue' or
                    self.digraph.node[edge[0]]['type'] == 'RegDeleteValue'):
                RegDeleteXe.append(self.pos[edge[0]][0])
                RegDeleteXe.append(self.pos[edge[1]][0])
                RegDeleteXe.append(None)
                RegDeleteYe.append(self.pos[edge[0]][1])
                RegDeleteYe.append(self.pos[edge[1]][1])
                RegDeleteYe.append(None)

        nodes = []
        edges = []

        # PROCESSES...

        marker = Marker(symbol='circle', size=10)

        # Create the nodes...
        ProcNodes = Scatter(x=ProcessX,
                            y=ProcessY,
                            mode='markers',
                            marker=marker,
                            name='Process',
                            text=proctxt,
                            hoverinfo='text')

        # Create the edges for the nodes...
        ProcEdges = Scatter(x=ProcessXe,
                            y=ProcessYe,
                            mode='lines',
                            line=Line(shape='linear'),
                            name='Process Start',
                            hoverinfo='none')

        nodes.append(ProcNodes)
        edges.append(ProcEdges)

        # TCP CONNECTIONS...

        if self.plottcpconnects is True:
            marker = Marker(symbol='diamond', size=7)

            # Create the nodes...
            TCPConnectNodes = Scatter(x=TCPConnectX,
                                      y=TCPConnectY,
                                      mode='markers',
                                      marker=marker,
                                      name='TCP Connections',
                                      text=tcpconntxt,
                                      hoverinfo='text')

            # Create the edges for the nodes...
            TCPConnectEdges = Scatter(x=TCPConnectXe,
                                      y=TCPConnectYe,
                                      mode='lines',
                                      line=Line(shape='linear'),
                                      name='TCP Connect',
                                      hoverinfo='none')

            nodes.append(TCPConnectNodes)
            edges.append(TCPConnectEdges)

        # UDP Receives...

        if self.plotudprecvs is True:
            marker = Marker(symbol='triangle-down', size=7)

            # Create the nodes...
            UDPReceiveNodes = Scatter(x=UDPReceiveX,
                                      y=UDPReceiveY,
                                      mode='markers',
                                      marker=marker,
                                      name='UDP Receives',
                                      text=udprectxt,
                                      hoverinfo='text')

            # Create the edges for the nodes...
            UDPReceiveEdges = Scatter(x=UDPReceiveXe,
                                      y=UDPReceiveYe,
                                      mode='lines',
                                      line=Line(shape='linear'),
                                      name='UDP Receive',
                                      hoverinfo='none')

            nodes.append(UDPReceiveNodes)
            edges.append(UDPReceiveEdges)

        # UDP Sends...

        if self.plotudpsends is True:
            marker = Marker(symbol='triangle-up', size=7)

            # Create the nodes...
            UDPSendNodes = Scatter(x=UDPSendX,
                                   y=UDPSendY,
                                   mode='markers',
                                   marker=marker,
                                   name='UDP Sends',
                                   text=udpsendtxt,
                                   hoverinfo='text')

            # Create the edges for the nodes...
            UDPSendEdges = Scatter(x=UDPSendXe,
                                   y=UDPSendYe,
                                   mode='lines',
                                   line=Line(shape='linear'),
                                   name='UDP Send',
                                   hoverinfo='none')

            nodes.append(UDPSendNodes)
            edges.append(UDPSendEdges)

        # HOSTS...
        if (self.plottcpconnects is True or
            self.plotudprecvs is True or
                self.plotudpsends is True):
            marker = Marker(symbol='square', size=10)

            # Create the nodes...
            HostNodes = Scatter(x=HostX,
                                y=HostY,
                                mode='markers',
                                marker=marker,
                                name='Hosts',
                                text=hosttxt,
                                hoverinfo='text')

            nodes.append(HostNodes)

        # File Writes...

        if self.plotfilewrites is True:
            marker = Marker(symbol='triangle-down', size=7)

            # Create the nodes...
            FileWriteNodes = Scatter(x=FileWriteX,
                                     y=FileWriteY,
                                     mode='markers',
                                     marker=marker,
                                     name='File Writes',
                                     text=filewritetxt,
                                     hoverinfo='text')

            # Create the edges for the nodes...
            FileWriteEdges = Scatter(x=FileWriteXe,
                                     y=FileWriteYe,
                                     mode='lines',
                                     line=Line(shape='linear'),
                                     name='File Write',
                                     hoverinfo='none')

            nodes.append(FileWriteNodes)
            edges.append(FileWriteEdges)

        # File Reads...

        if self.plotfilereads is True:
            marker = Marker(symbol='triangle-up', size=7)

            # Create the nodes...
            FileReadNodes = Scatter(x=FileReadX,
                                    y=FileReadY,
                                    mode='markers',
                                    marker=marker,
                                    name='File Reads',
                                    text=filereadtxt,
                                    hoverinfo='text')

            # Create the edges for the nodes...
            FileReadEdges = Scatter(x=FileReadXe,
                                    y=FileReadYe,
                                    mode='lines',
                                    line=Line(shape='linear'),
                                    name='File Read',
                                    hoverinfo='none')

            nodes.append(FileReadNodes)
            edges.append(FileReadEdges)

        # File Deletes...

        if self.plotfiledeletes is True:
            marker = Marker(symbol='triangle-down', size=7)

            # Create the nodes...
            FileDeleteNodes = Scatter(x=FileDeleteX,
                                      y=FileDeleteY,
                                      mode='markers',
                                      marker=marker,
                                      name='File Deletes',
                                      text=filedeletetxt,
                                      hoverinfo='text')

            # Create the edges for the nodes...
            FileDeleteEdges = Scatter(x=FileDeleteXe,
                                      y=FileDeleteYe,
                                      mode='lines',
                                      line=Line(shape='linear'),
                                      name='File Delete',
                                      hoverinfo='none')

            nodes.append(FileDeleteNodes)
            edges.append(FileDeleteEdges)

        # File Renames...

        if self.plotfilerenames is True:
            marker = Marker(symbol='triangle-down', size=7)

            # Create the nodes...
            FileRenameNodes = Scatter(x=FileRenameX,
                                      y=FileRenameY,
                                      mode='markers',
                                      marker=marker,
                                      name='File Renames',
                                      text=filerenametxt,
                                      hoverinfo='text')

            # Create the edges for the nodes...
            FileRenameEdges = Scatter(x=FileRenameXe,
                                      y=FileRenameYe,
                                      mode='lines',
                                      line=Line(shape='linear'),
                                      name='File Rename',
                                      hoverinfo='none')

            nodes.append(FileRenameNodes)
            edges.append(FileRenameEdges)

        # Files...
        if (self.plotfilereads is True or
            self.plotfilewrites is True or
            self.plotfiledeletes is True or
                self.plotfilerenames is True):
            marker = Marker(symbol='hexagon', size=10)

            # Create the nodes...
            FileNodes = Scatter(x=FileX,
                                y=FileY,
                                mode='markers',
                                marker=marker,
                                name='Files',
                                text=filetxt,
                                hoverinfo='text')

            # Create the edges for processes from files...
            FileImageEdges = Scatter(x=FileImageXe,
                                     y=FileImageYe,
                                     mode='lines',
                                     line=Line(shape='linear',
                                               dash='dot'),
                                     name='Process Load Image',
                                     hoverinfo='none')

            FileRenamedEdges = Scatter(x=FileRenamedXe,
                                       y=FileRenamedYe,
                                       mode='lines',
                                       line=Line(shape='linear',
                                                 dash='dot'),
                                       name='File Renamed',
                                       hoverinfo='none')

            nodes.append(FileNodes)
            edges.append(FileImageEdges)
            edges.append(FileRenamedEdges)

        # Reg Writes...

        if self.plotregwrites is True:
            marker = Marker(symbol='triangle-down', size=7)

            # Create the nodes...
            RegWriteNodes = Scatter(x=RegWriteX,
                                    y=RegWriteY,
                                    mode='markers',
                                    marker=marker,
                                    name='Registry Writes',
                                    text=regwritetxt,
                                    hoverinfo='text')

            # Create the edges for the nodes...
            RegWriteEdges = Scatter(x=RegWriteXe,
                                    y=RegWriteYe,
                                    mode='lines',
                                    line=Line(shape='linear'),
                                    name='Registry Write',
                                    hoverinfo='none')

            nodes.append(RegWriteNodes)
            edges.append(RegWriteEdges)

        # Reg Reads...

        if self.plotregreads is True:
            marker = Marker(symbol='triangle-up', size=7)

            # Create the nodes...
            RegReadNodes = Scatter(x=RegReadX,
                                   y=RegReadY,
                                   mode='markers',
                                   marker=marker,
                                   name='Registry Reads',
                                   text=regreadtxt,
                                   hoverinfo='text')

            # Create the edges for the nodes...
            RegReadEdges = Scatter(x=RegReadXe,
                                   y=RegReadYe,
                                   mode='lines',
                                   line=Line(shape='linear'),
                                   name='Registry Read',
                                   hoverinfo='none')

            nodes.append(RegReadNodes)
            edges.append(RegReadEdges)

        # Reg Deletes...

        if self.plotregdeletes is True:
            marker = Marker(symbol='triangle-down', size=7)

            # Create the nodes...
            RegDeleteNodes = Scatter(x=RegDeleteX,
                                     y=RegDeleteY,
                                     mode='markers',
                                     marker=marker,
                                     name='Registry Deletes',
                                     text=regdeletetxt,
                                     hoverinfo='text')

            # Create the edges for the nodes...
            RegDeleteEdges = Scatter(x=RegDeleteXe,
                                     y=RegDeleteYe,
                                     mode='lines',
                                     line=Line(shape='linear'),
                                     name='Registry Delete',
                                     hoverinfo='none')

            nodes.append(RegDeleteNodes)
            edges.append(RegDeleteEdges)

        # Registry...
        if (self.plotregreads is True or
            self.plotregwrites is True or
                self.plotregdeletes is True):
            marker = Marker(symbol='star', size=10)

            # Create the nodes...
            RegNodes = Scatter(x=RegX,
                               y=RegY,
                               mode='markers',
                               marker=marker,
                               name='Registry Values',
                               text=regtxt,
                               hoverinfo='text')

            nodes.append(RegNodes)

        # Reverse the order and mush...
        output = []
        output += edges[::-1]
        output += nodes[::-1]

        # Return the plot data...
        return output

    def _generateannotations(self):
        """

        Internal function to generate annotations.

        :returns:  Annotations for plotly.

        """
        annotations = Annotations()

        for node in self.digraph:
            if self.digraph.node[node]['type'] == 'Process Start':
                if self.showproclabels is True:
                    annotations.append(
                        Annotation(
                            text="{0}<br>PID: {1}".format(
                                self.nodemetadata[node]['Process Name'],
                                self.nodemetadata[node]['PID']
                                ),
                            x=self.pos[node][0],
                            y=self.pos[node][1],
                            xref='x',
                            yref='y',
                            showarrow=True,
                            ax=-40,
                            ay=-40
                            )
                        )
            if self.digraph.node[node]['type'] == 'Unknown PID':
                if self.showproclabels is True:
                    if node not in self.unkpidcmdline:
                        annotations.append(
                            Annotation(
                                text="UNKNOWN<br>PID: {0}".format(
                                    self.digraph.node[node]['pid']
                                    ),
                                x=self.pos[node][0],
                                y=self.pos[node][1],
                                xref='x',
                                yref='y',
                                showarrow=True,
                                ax=-40,
                                ay=-40
                                )
                            )
                    else:
                        annotations.append(
                            Annotation(
                                text="{1}<br>PID: {0}".format(
                                    self.digraph.node[node]['pid'],
                                    self.unkpidcmdline[node][0]
                                    ),
                                x=self.pos[node][0],
                                y=self.pos[node][1],
                                xref='x',
                                yref='y',
                                showarrow=True,
                                ax=-40,
                                ay=-40
                                )
                            )
            if self.digraph.node[node]['type'] == 'TCP Connect':
                if self.showtcplabels is True:
                    annotations.append(
                        Annotation(
                            text="TCP Connect<br>{0}<br>"
                                 "Time: {1}"
                                 .format(
                                         self.nodemetadata[node]['Path'],
                                         self.nodemetadata[node]['Time']
                                         ),
                            x=self.pos[node][0],
                            y=self.pos[node][1],
                            xref='x',
                            yref='y',
                            showarrow=True,
                            ax=-40,
                            ay=-40
                            )
                        )
            if self.digraph.node[node]['type'] == 'UDP Receive':
                if self.showudplabels is True:
                    annotations.append(
                        Annotation(
                            text="UDP Receive<br>{0}<br>"
                                 "Time: {1}"
                                 .format(
                                         self.nodemetadata[node]['Path'],
                                         self.nodemetadata[node]['Time']
                                         ),
                            x=self.pos[node][0],
                            y=self.pos[node][1],
                            xref='x',
                            yref='y',
                            showarrow=True,
                            ax=-40,
                            ay=-40
                            )
                        )
            if self.digraph.node[node]['type'] == 'UDP Send':
                if self.showudplabels is True:
                    annotations.append(
                        Annotation(
                            text="UDP Send<br>{0}<br>"
                                 "Time: {1}"
                                 .format(
                                         self.nodemetadata[node]['Path'],
                                         self.nodemetadata[node]['Time']
                                         ),
                            x=self.pos[node][0],
                            y=self.pos[node][1],
                            xref='x',
                            yref='y',
                            showarrow=True,
                            ax=-40,
                            ay=-40
                            )
                        )
            if self.digraph.node[node]['type'] == 'host':
                if self.showhostlabels is True:
                    annotations.append(
                        Annotation(
                            text="Host<br>{0}".format(
                                 self.digraph.node[node]['host'][1:-1]
                                ),
                            x=self.pos[node][0],
                            y=self.pos[node][1],
                            xref='x',
                            yref='y',
                            showarrow=True,
                            ax=-40,
                            ay=-40
                            )
                        )
            if self.digraph.node[node]['type'] == 'WriteFile':
                if self.showfilelabels is True:
                    annotations.append(
                        Annotation(
                            text="WRITE",
                            x=self.pos[node][0],
                            y=self.pos[node][1],
                            xref='x',
                            yref='y',
                            showarrow=True,
                            ax=-40,
                            ay=-40
                            )
                        )
            if self.digraph.node[node]['type'] == 'ReadFile':
                if self.showfilelabels is True:
                    annotations.append(
                        Annotation(
                            text="READ",
                            x=self.pos[node][0],
                            y=self.pos[node][1],
                            xref='x',
                            yref='y',
                            showarrow=True,
                            ax=-40,
                            ay=-40
                            )
                        )
            if (self.digraph.node[node]['type']
                    == 'SetDispositionInformationFile'):
                if self.showfilelabels is True:
                    annotations.append(
                        Annotation(
                            text="DELETE",
                            x=self.pos[node][0],
                            y=self.pos[node][1],
                            xref='x',
                            yref='y',
                            showarrow=True,
                            ax=-40,
                            ay=-40
                            )
                        )
            if (self.digraph.node[node]['type']
                    == 'SetRenameInformationFile'):
                if self.showfilelabels is True:
                    annotations.append(
                        Annotation(
                            text="RENAME",
                            x=self.pos[node][0],
                            y=self.pos[node][1],
                            xref='x',
                            yref='y',
                            showarrow=True,
                            ax=-40,
                            ay=-40
                            )
                        )
            if self.digraph.node[node]['type'] == 'file':
                if self.showfilelabels is True:
                    for f in self.filetable:
                        if (self.filetable[f] ==
                                self.digraph.node[node]['filenum']):
                            filename = f
                            break
                    annotations.append(
                        Annotation(
                            text="File<br>{0}".format(filename),
                            x=self.pos[node][0],
                            y=self.pos[node][1],
                            xref='x',
                            yref='y',
                            showarrow=True,
                            ax=-40,
                            ay=-40
                            )
                        )
            if self.digraph.node[node]['type'] == 'RegSetValue':
                if self.showreglabels is True:
                    annotations.append(
                        Annotation(
                            text="WRITE",
                            x=self.pos[node][0],
                            y=self.pos[node][1],
                            xref='x',
                            yref='y',
                            showarrow=True,
                            ax=-40,
                            ay=-40
                            )
                        )
            if self.digraph.node[node]['type'] == 'RegQueryValue':
                if self.showreglabels is True:
                    annotations.append(
                        Annotation(
                            text="READ",
                            x=self.pos[node][0],
                            y=self.pos[node][1],
                            xref='x',
                            yref='y',
                            showarrow=True,
                            ax=-40,
                            ay=-40
                            )
                        )
            if (self.digraph.node[node]['type'] == 'RegDeleteValue'):
                if self.showreglabels is True:
                    annotations.append(
                        Annotation(
                            text="DELETE",
                            x=self.pos[node][0],
                            y=self.pos[node][1],
                            xref='x',
                            yref='y',
                            showarrow=True,
                            ax=-40,
                            ay=-40
                            )
                        )
            if self.digraph.node[node]['type'] == 'reg':
                if self.showreglabels is True:
                    for r in self.regtable:
                        if (self.regtable[r] ==
                                self.digraph.node[node]['regnum']):
                            regname = r
                            break
                    annotations.append(
                        Annotation(
                            text="Registry<br>{0}".format(regname),
                            x=self.pos[node][0],
                            y=self.pos[node][1],
                            xref='x',
                            yref='y',
                            showarrow=True,
                            ax=-40,
                            ay=-40
                            )
                        )

        return annotations

    def plotgraph(self,
                  graphvizprog='sfdp',
                  showproclabels=True,
                  showtcplabels=True,
                  showudplabels=True,
                  showfilelabels=True,
                  showhostlabels=True,
                  showreglabels=True,
                  plottcpconnects=True,
                  plotudpsends=True,
                  plotudprecvs=True,
                  plotfilereads=True,
                  plotfilewrites=True,
                  plotfiledeletes=True,
                  plotfilerenames=True,
                  plotregwrites=True,
                  plotregreads=True,
                  plotregdeletes=True,
                  ignorepaths=None,
                  includepaths=None,
                  filename='temp-plot.html',
                  title=None, auto_open=True,
                  image=None, image_filename='plot_image',
                  image_height=600, image_width=800):
        """

        Function to plot the graph of the ProcMon CSV.

        :param graphvizprog: The graphviz program to use for layout, valid
            options are 'dot', 'neato', 'twopi', 'circo', 'fdp',
            'sfdp', 'patchwork', and 'osage'.  Graphviz is REQUIRED to be
            installed and in your path to use this library!  The associated
            layout programs must be available in your path as well.  More
            information for the layout types can be found here:
            http://www.graphviz.org/Documentation.php
            If this value is None, the internal networkx layout algorithms
            will be used.
        :param showproclabels: If True will turn on labels on the processes.
            Set to False to clean up your plot and not show the labels.
            The data can be viewed with mouse overs either way.
        :param showtcplabels: If True will turn on labels on the TCP connects.
            Set to False to clean up your plot and not show the labels.
            The data can be viewed with mouse overs either way.
        :param showudplabels: If True will turn on labels on the UDP traffic.
            Set to False to clean up your plot and not show the labels.
            The data can be viewed with mouse overs either way.
        :param showfilelabels:  If True will turn on labels on the File IO.
            Set to False to clean up your plot and not show the labels.
            The data can be viewed with mouse overs either way.
        :param showhostlabels:  If True will turn on labels for the hosts.
            Set to False to clean up your plot and not show the labels.
            The data can be viewed with mouse overs either way.
        :param showhostlabels:  If True will turn on labels for registry.
            Set to False to clean up your plot and not show the labels.
            The data can be viewed with mouse overs either way.
        :param plottcpconnects: Set to False to remove TCP connections.
        :param plotudpsends: Set to False to remove UDP sends.  This option
            can be noisy if True.
        :param plotudprecvs: Set to False to remove UDP receives.  This option
            can be noisy if True.
        :param plotfilereads: Set to False to remove File Reads.
        :param plotfilewrites: Set to False to remove File Writes.
        :param plotfiledeletes: Set to False to remove File Deletes.
        :param plotfilerenames: Set to False to remove File Renames.
        :param plotregwrites: Set to False to remove registry writes.
        :param plotregreads: Set to False to remove registry reads.
        :param plotregdeletes: Set to False to remove registry deletes.
        :param ignorepaths: Set this to a list of regular expressions.  If the
            regular expression fires in the Path column, that event will not be
            plotted.  Set to None to ignore this option.  This is case
            insensitive.  Remember to double escape since this is
            interpreted twice!
        :param includepaths:  Set this to a list of regular expressions.
            If the regular expression fires in the Path column, that event will
            be plotted.  This overrides ignores from ignorepaths above.
            Set to None to ignore this option.  This is case insensitive.
            Remember to double escape since this is interpreted twice!
        :param filename: A file name for the interactive HTML plot.
        :param title: A title for the plot.
        :param auto_open: Set to false to not open the file in a web browser.
        :param image: An image type of 'png', 'jpeg', 'svg', 'webp', or None.
        :param image_filename: The file name for the exported image.
        :param image_height: The number of pixels for the image height.
        :param image_width: The number of pixels for the image width.
        :returns: Nothing

        """

        # Set up our options...
        self.graphvizprog = graphvizprog
        self.showproclabels = showproclabels
        self.showtcplabels = showtcplabels
        self.showudplabels = showudplabels
        self.showfilelabels = showfilelabels
        self.showproclabels = showproclabels
        self.showhostlabels = showhostlabels
        self.showreglabels = showreglabels
        self.plottcpconnects = plottcpconnects
        self.plotudprecvs = plotudprecvs
        self.plotudpsends = plotudpsends
        self.plotfilereads = plotfilereads
        self.plotfilewrites = plotfilewrites
        self.plotfiledeletes = plotfiledeletes
        self.plotfilerenames = plotfilerenames
        self.plotregwrites = plotregwrites
        self.plotregreads = plotregreads
        self.plotregdeletes = plotregdeletes

        if ignorepaths is not None and isinstance(ignorepaths, list):
            self.ignorepaths += ignorepaths
        elif ignorepaths is not None and not isinstance(ignorepaths, list):
            raise VisualizeLogsBadFunctionInput('ignorepaths')

        if includepaths is not None and isinstance(includepaths, list):
            self.includefiles += includepaths
        elif includepaths is not None and not isinstance(includepaths, list):
            raise VisualizeLogsBadFunctionInput('includepaths')

        # Construct a new graph...
        outputdata = self._constructgraph()
        annotations = self._generateannotations()

        # Hide axis line, grid, ticklabels and title...
        axis = dict(showline=False,
                    zeroline=False,
                    showgrid=False,
                    showticklabels=False,
                    title='')

        plotlayout = Layout(showlegend=True, title=title,
                            xaxis=XAxis(axis),
                            yaxis=YAxis(axis),
                            hovermode='closest',
                            annotations=annotations)

        plotfigure = Figure(data=outputdata,
                            layout=plotlayout)

        # Plot without the plotly annoying link...
        plot(plotfigure, show_link=False, filename=filename,
             auto_open=auto_open, image=image,
             image_filename=image_filename,
             image_height=image_height,
             image_width=image_width)


class VisualizeLogsInvalidFile(Exception):
    """

    Exception for when a file does not exist or is invalid.

    """
    def __init__(self, filepath):
        Exception.__init__(self, "Visualize_Logs: Invalid File {0}"
                                 .format(filepath))


class VisualizeLogsInvalidFileStructure(Exception):
    """

    Exception for when a file's content is not structured correctly.

    """
    def __init__(self, filepath):
        Exception.__init__(self, "Visualize_Logs: Invalid File Content {0}"
                                 .format(filepath))


class VisualizeLogsMissingRequiredField(Exception):
    """

    Exception for when a file's content is missing a data field.

    """
    def __init__(self, filepath, field):
        Exception.__init__(self, "Visualize_Logs: Missing Field {0} in {1}"
                                 .format(field, filepath))


class VisualizeLogsBadFunctionInput(Exception):
    """

    Exception for when bad input is given to a function.

    """
    def __init__(self, inputname):
        Exception.__init__(self, "Visualize_Logs: Bad Function Input: {0}"
                                 .format(inputname))


class VisualizeLogsParseError(Exception):
    """

    Exception for when data cannot be parsed correctly.

    """
    def __init__(self, data):
        Exception.__init__(self, "Visualize_Logs: Cannot parse: {0}"
                                 .format(data))
