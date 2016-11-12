#
# Includes
#

# NetworkX
import networkx

# OS
import os

# Pandas
import pandas

# Plotly
from plotly.offline import plot
from plotly.graph_objs import Bar, Scatter, Figure, Layout, \
    Line, Marker, Annotations, Annotation, XAxis, YAxis

# Regular Expressions
import re

# JSON
import json

# Exceptions
from . import Exceptions

#
# Classes
#


class CuckooJSONReport(object):
    """
    Class to hold Cuckoo-Modified JSON reports.

    https://github.com/spender-sandbox/cuckoo-modified
    """
    jsonreportfile = None
    """The JSON report file path."""

    jsonreportdata = None
    """This holds the actual data of the JSON report."""

    DiGraph = None
    """This holds the Networkx digraph to be plotted."""

    graphvizprog = None
    """This is the graphviz program used to generate the layout."""

    nodemetadata = dict()
    """This is a dict that will hold dicts of metadata for each node."""

    edgemetadata = dict()
    """This is a dict of (edge1,edge2) that will hold dicts of metadata
    for each edge."""

    rootpid = None
    """This is the pid (Node) on top."""

    ignorepaths = []
    """List of regular expressions to ignore in file or registry data."""

    includepaths = []
    """List of regular expressions to include in file or registry data."""

    IPProto = {
                0: 'IPPROTO_IP',
                1: 'IPPROTO_ICMP',
                4: 'IPPROTO_IGMP',
                6: 'IPPROTO_TCP',
                8: 'IPPROTO_EGP',
                12: 'IPPROTO_PUP',
                17: 'IPPROTO_UDP',
                29: 'IPPROTO_IDP',
                33: 'IPPROTO_DCCP',
                41: 'IPPROTO_IPV6',
                46: 'IPPROTO_RSVP',
                47: 'IPPROTO_GRE',
                50: 'IPPROTO_ESP',
                51: 'IPPROTO_AH',
                92: 'IPPROTO_MTP',
                94: 'IPPROTO_BEETPH',
                98: 'IPPROTO_ENCAP',
                103: 'IPPROTO_PIM',
                108: 'IPPROTO_COMP',
                132: 'IPPROTO_SCTP',
                136: 'IPPROTO_UDPLITE',
                137: 'IPPROTO_MPLS',
                255: 'IPPROTO_RAW'
                }
    """Information available:
    http://lxr.free-electrons.com/source/include/uapi/linux/in.h"""

    def __init__(self, jsonreportfile=None,
                 jsonreportdict=None,
                 plotnetwork=True,
                 plotfiles=True,
                 plotfilecreates=True,
                 plotfiledeletes=True,
                 plotfilemoves=True,
                 plotfilecopies=True,
                 plotfilewrites=True,
                 plotfilereads=True,
                 plotregistry=True,
                 plotregistrywrites=True,
                 plotregistryreads=True,
                 plotregistrydeletes=True,
                 plotregistrycreates=True,
                 ignorepaths=None,
                 includepaths=None):
        """
        The JSON report file is read and parsed using this class.  This
        could take a whiel depending on how big your JSON report is.

        This has been tested with the cuckoo-modifed version, but it may
        work with Cuckoo (proper) as well.

        :param jsonreportfile: The path to the JSON report file.  Set to
            None to use a jsonreportstring.
        :type jsonreportfile: A string.
        :param jsonreportdict: A dict containing a JSON
            report file loaded with JSON load.
            Set to None to use a jsonreportfile.
        :param plotnetwork: Set to False to ignore network activity.
        :param plotfiles: Set to False to ignore file activity.
        :param plotfilecreates: Set to False to ignore file creates.
        :param plotfiledeletes: Set to False to ignore file deletes.
        :param plotfilemoves: Set to False to ignore file moves.
        :param plotfilecopies: Set to False to ignore file copies.
        :param plotfilewrites: Set to False to ignore file writes.
        :param plotfilereads: Set to False to ignore file reads.
        :param plotregistry: Set to False to ignore registry activity.
        :param plotregistrywrites: Set to False to ignore registry writes.
        :param plotregistryreads: Set to False to ignore registry reads.
        :param plotregistrydeletes: Set to False to ignore registry deletes.
        :param plotregistrycreates: Set to False to ignore registry creates.
        :param ignorepaths: A list of regular expressions to ignore for
            files and registry values.
        :param includepaths: A list of regular expressions to include for
            files and registry values.  Overrides ignore paths.
        :returns: An object.
        :rtype: CuckooJSONReport object.
        """
        self.plotfilecreates = plotfilecreates
        self.plotfiledeletes = plotfiledeletes
        self.plotfilemoves = plotfilemoves
        self.plotfilecopies = plotfilecopies
        self.plotfilewrites = plotfilewrites
        self.plotfilereads = plotfilereads

        self.plotregistrywrites = plotregistrywrites
        self.plotregistryreads = plotregistryreads
        self.plotregistrydeletes = plotregistrydeletes
        self.plotregistrycreates = plotregistrycreates

        if ignorepaths is not None and isinstance(ignorepaths, list):
            self.ignorepaths = ignorepaths

        if includepaths is not None and isinstance(includepaths, list):
            self.includepaths = includepaths

        if jsonreportfile is not None:
            if not os.path.exists(jsonreportfile):
                raise Exceptions.VisualizeLogsInvalidFile(jsonreportfile)
            else:
                self.jsonreportfile = jsonreportfile

            with open(self.jsonreportfile, 'r') as jsonfile:
                self.jsonreportdata = json.load(jsonfile)
        elif jsonreportdict is not None:
            self.jsonreportfile = None
            self.jsonreportdata = jsonreportdict
        else:
            raise Exceptions.VisualizeLogsBadFunctionInput("jsonreportfile")

        # Create a network graph...
        self.digraph = networkx.DiGraph()

        # Add all the processes to the graph...
        self._add_all_processes()

        if plotnetwork is True:
            # Add network activity to the graph...
            self._add_network_activity()

        if plotfiles is True:
            # Add file activity to the graph...
            self._add_file_activity()

        if plotregistry is True:
            # Add registry activity to the graph...
            self._add_registry_activity()

    def _search_re(self, string, expressions):
        """
        Internal function to check if string is selected
        by regular expressions in expression list.
        Ignores case!

        :param string:  String to search.
        :param expressions: List of regular expressions to search.
        :returns: True if expressions fire on string, False otherwise.
        """
        for e in expressions:
            m = re.search(string, e, re.IGNORECASE)
            if m:
                return True

        return False

    def _add_all_processes(self):
        """
        Internal function to add processess from JSON report
        process tree.

        :returns: Nothing.
        """
        self._processtree = self.jsonreportdata['behavior']['processtree']
        self._processes = self.jsonreportdata['behavior']['processes']

        self.rootpid = "PID {0}".format(self._processtree[0]['pid'])

        for process in self._processtree:
            self._add_processes_recursive(process)

        # Add the rest of the metadata...
        self._add_process_metadata()

    def _add_processes_recursive(self, processtreedict):
        """
        Internal function to add processes recursively from
        a dict representing the JSON process tree.

        :param processtreedict:  A dict of data from the process tree.
        :returns: Nothing.
        """
        pid = processtreedict['pid']
        ppid = processtreedict['parent_id']
        nodename = "PID {0}".format(pid)
        ppid_node = "PID {0}".format(ppid)

        self.digraph.add_node(nodename,
                              type='PID',
                              pid=pid,
                              parent_id=ppid)

        self.nodemetadata[nodename] = dict()
        self.nodemetadata[nodename]['node_type'] = 'PID'
        self.nodemetadata[nodename]['pid'] = pid
        self.nodemetadata[nodename]['parent_id'] = ppid
        self.nodemetadata[nodename]['threads'] = processtreedict['threads']
        # self.nodemetadata[nodename]['environ'] = processtreedict['environ']
        self.nodemetadata[nodename]['name'] = processtreedict['name']
        self.nodemetadata[nodename]['module_path'] =\
            processtreedict['module_path']
        self.nodemetadata[nodename]['children'] = list()

        if ppid_node not in self.nodemetadata:
            self.nodemetadata[ppid_node] = dict()
            self.nodemetadata[ppid_node]['node_type'] = 'PID'
            self.nodemetadata[ppid_node]['children'] = list()
            self.nodemetadata[ppid_node]['cmdline'] = ""

        self.nodemetadata[ppid_node]['children'].append(nodename)

        if ppid_node in self.digraph:
            self.digraph.add_edge(ppid_node, nodename)

        for child in processtreedict['children']:
            self._add_processes_recursive(child)

    def _add_process_metadata(self):
        """
        Internal function that ties the extra process metadata
        to the nodemetadata dict.

        :returns: Nothing.
        """
        for process in self._processes:
            nodename = "PID {0}".format(process['process_id'])
            self.nodemetadata[nodename]['first_seen'] = process['first_seen']
            self.nodemetadata[nodename]['calls'] =\
                pandas.DataFrame(process['calls'])
            self.nodemetadata[nodename]['calls']['timestamp'] =\
                pandas.to_datetime(
                    self.nodemetadata[nodename]['calls']['timestamp'])
            self.nodemetadata[nodename]['calls'] =\
                self.nodemetadata[nodename]['calls'].sort_values(['timestamp'])

            calls = self.nodemetadata[nodename]['calls']

            createprocs = calls[calls['api'] == 'CreateProcessInternalW']

            for i, createproc in createprocs.iterrows():
                childpid = None
                cmdline = None
                for arg in createproc['arguments']:
                    if arg['name'] == 'ProcessId':
                        childpid = arg['value']
                    if arg['name'] == 'CommandLine':
                        cmdline = arg['value']

                if cmdline is None:
                    cmdline = "Not Available"

                if childpid is not None:
                    childnode = "PID {0}".format(childpid)
                    self.nodemetadata[childnode]['cmdline'] = cmdline

    def _add_file_activity(self):
        """
        Internal function that adds file data to the graph.
        Assumes processes have already been plotted.

        :returns:  Nothing.
        """
        metadata = self.nodemetadata.copy()
        for node in metadata:
            if metadata[node]['node_type'] == 'PID':
                if 'calls' in metadata[node]:
                    calls = metadata[node]['calls']

                    # Get file creates...
                    if self.plotfilecreates is True:
                        self._add_file_creates(node, calls)

                    # Get file writes...
                    if self.plotfilewrites is True:
                        self._add_file_writes(node, calls)

                    # Get file reads...
                    if self.plotfilereads is True:
                        self._add_file_reads(node, calls)

                    # Get file copies...
                    if self.plotfilecopies is True:
                        self._add_file_copies(node, calls)

                    # Get file deletes...
                    if self.plotfiledeletes is True:
                        self._add_file_deletes(node, calls)

                    # Get file moves...
                    if self.plotfilemoves is True:
                        self._add_file_moves(node, calls)

                    # Connect PIDs to files
                    self._connect_file_to_pid()

    def _connect_file_to_pid(self):
        """
        Internal function that will connect files to PIDs.

        :returns:  Nothing.
        """
        for node in self.nodemetadata:
            if (self.nodemetadata[node]['node_type'] == 'PID' and
                    'module_path' in self.nodemetadata[node]):
                pidpath = self.nodemetadata[node]['module_path']
                for linknode in self.nodemetadata:
                    if self.nodemetadata[linknode]['node_type'] == 'FILE':
                        filepath = self.nodemetadata[linknode]['file']
                        if pidpath == filepath:
                            self.digraph.add_edge(linknode, node)

    def _add_file_moves(self, node, calls):
        """
        Internal function that adds the file moves in the calls
        for the PID node.

        :param node: PID node name.
        :param calls:  Calls for node.
        :returns: Nothing.
        """
        filemoves = calls[((calls['api'] == 'MoveFileW') |
                          (calls['api'] == 'MoveFileA') |
                          (calls['api'] == 'MoveFileWithProgressW') |
                          (calls['api'] == 'MoveFileWithProgressA')) &
                          (calls['status'] == True)]

        for i, filemove in filemoves.iterrows():
            existingfilename = None
            newfilename = None
            for arg in filemove['arguments']:
                if arg['name'] == 'ExistingFileName':
                    existingfilename = arg['value']
                if arg['name'] == 'NewFileName':
                    newfilename = arg['value']
            if newfilename is not None:
                if (self._search_re(newfilename, self.ignorepaths) and
                        not self._search_re(newfilename, self.includepaths)):
                    continue

                newfilenodename = self._add_file(newfilename)
                existingfilenodename = self._add_file(existingfilename)
                # Get a sequential number for the event...
                nextid = len(self.nodemetadata)
                fmnodename = "FILE MOVE {0}".format(nextid)
                self.nodemetadata[fmnodename] = dict()
                self.nodemetadata[fmnodename]['existingfile'] =\
                    existingfilename
                self.nodemetadata[fmnodename]['newfile'] = newfilename
                self.nodemetadata[fmnodename]['node_type'] = 'FILEMOVE'
                self.nodemetadata[fmnodename]['timestamp'] =\
                    filemove['timestamp']
                self.digraph.add_node(fmnodename, type='FILEMOVE')

                self.digraph.add_edge(node, fmnodename)
                self.digraph.add_edge(fmnodename, newfilenodename)
                self.digraph.add_edge(fmnodename, existingfilenodename)

    def _add_file_copies(self, node, calls):
        """
        Internal function that adds the file copies in the calls
        for the PID node.

        :param node: PID node name.
        :param calls:  Calls for node.
        :returns: Nothing.
        """
        filecopies = calls[((calls['api'] == 'CopyFileW') |
                            (calls['api'] == 'CopyFileA')) &
                           (calls['status'] == True)]

        for i, filecreate in filecopies.iterrows():
            existedbefore = None
            existingfilename = None
            newfilename = None
            for arg in filecreate['arguments']:
                if arg['name'] == 'ExistingFileName':
                    existingfilename = arg['value']
                if arg['name'] == 'ExistedBefore':
                    existedbefore = arg['value']
                if arg['name'] == 'NewFileName':
                    newfilename = arg['value']
            if newfilename is not None:
                if (self._search_re(newfilename, self.ignorepaths) and
                        not self._search_re(newfilename, self.includepaths)):
                    continue
                if (self._search_re(existingfilename, self.ignorepaths) and
                    not
                        self._search_re(existingfilename, self.includepaths)):
                    continue
                newfilenodename = self._add_file(newfilename)
                existingfilenodename = self._add_file(existingfilename)
                # Get a sequential number for the event...
                nextid = len(self.nodemetadata)
                fcnodename = "FILE COPY {0}".format(nextid)
                self.nodemetadata[fcnodename] = dict()
                self.nodemetadata[fcnodename]['existingfile'] =\
                    existingfilename
                self.nodemetadata[fcnodename]['newfile'] = newfilename
                self.nodemetadata[fcnodename]['node_type'] = 'FILECOPY'
                self.nodemetadata[fcnodename]['existedbefore'] = existedbefore
                self.nodemetadata[fcnodename]['timestamp'] =\
                    filecreate['timestamp']
                self.digraph.add_node(fcnodename, type='FILECOPY')

                self.digraph.add_edge(node, fcnodename)
                self.digraph.add_edge(fcnodename, newfilenodename)
                self.digraph.add_edge(fcnodename, existingfilenodename)

    def _add_file_deletes(self, node, calls):
        """
        Internal function that adds the file deletes in the calls
        for the PID node.

        :param node: PID node name.
        :param calls:  Calls for node.
        :returns: Nothing.
        """
        filedeletes = calls[((calls['api'] == 'DeleteFileW') |
                             (calls['api'] == 'DeleteFileA')) &
                            (calls['status'] == True)]

        for i, filedelete in filedeletes.iterrows():
            filename = None
            for arg in filedelete['arguments']:
                if arg['name'] == 'FileName':
                    filename = arg['value']
            if filename is not None:
                if (self._search_re(filename, self.ignorepaths) and
                        not self._search_re(filename, self.includepaths)):
                    continue
                filenodename = self._add_file(filename)
                # Get a sequential number for the event...
                nextid = len(self.nodemetadata)
                fdnodename = "FILE DELETE {0}".format(nextid)
                self.nodemetadata[fdnodename] = dict()
                self.nodemetadata[fdnodename]['file'] =\
                    filename
                self.nodemetadata[fdnodename]['node_type'] = 'FILEDELETE'
                self.nodemetadata[fdnodename]['timestamp'] =\
                    filedelete['timestamp']
                self.digraph.add_node(fdnodename, type='FILEDELETE')

                self.digraph.add_edge(node, fdnodename)
                self.digraph.add_edge(fdnodename, filenodename)

    def _add_file_creates(self, node, calls):
        """
        Internal function that adds the file creates in the calls
        for the PID node.

        :param node: PID node name.
        :param calls:  Calls for node.
        :returns: Nothing.
        """
        filecreates = calls[(calls['api'] == 'NtCreateFile') &
                            (calls['status'] == True)]

        for i, filecreate in filecreates.iterrows():
            filename = None
            existedbefore = None
            desiredaccess = None
            createdisposition = None
            fileattribtes = None
            for arg in filecreate['arguments']:
                if arg['name'] == 'FileName':
                    filename = arg['value']
                if arg['name'] == 'ExistedBefore':
                    existedbefore = arg['value']
                if arg['name'] == 'DesiredAccess':
                    desiredaccess = arg['value']
                if arg['name'] == 'CreateDisposition':
                    createdisposition = arg['value']
                if arg['name'] == 'FileAttributes':
                    fileattribtes = arg['value']
            if filename is not None:
                if (self._search_re(filename, self.ignorepaths) and
                        not self._search_re(filename, self.includepaths)):
                    continue
                filenodename = self._add_file(filename)
                # Get a sequential number for the event...
                nextid = len(self.nodemetadata)
                fcnodename = "FILE CREATE {0}".format(nextid)
                self.nodemetadata[fcnodename] = dict()
                self.nodemetadata[fcnodename]['file'] = filename
                self.nodemetadata[fcnodename]['node_type'] = 'FILECREATE'
                self.nodemetadata[fcnodename]['existedbefore'] = existedbefore
                self.nodemetadata[fcnodename]['desiredaccess'] = desiredaccess
                self.nodemetadata[fcnodename]['createdisposition'] =\
                    createdisposition
                self.nodemetadata[fcnodename]['fileattribtes'] =\
                    fileattribtes
                self.nodemetadata[fcnodename]['timestamp'] =\
                    filecreate['timestamp']
                self.digraph.add_node(fcnodename, type='FILECREATE')

                self.digraph.add_edge(node, fcnodename)
                self.digraph.add_edge(fcnodename, filenodename)

    def _add_file_writes(self, node, calls):
        """
        Internal function that adds the file writes in the calls for
        the PID node.

        :param node:  PID node name.
        :param calls:  Calls for node.
        :returns: Nothing.
        """
        filewrites = calls[(calls['api'] == 'NtWriteFile') &
                           (calls['status'] == True)]

        for i, filewrite in filewrites.iterrows():
            filename = None
            for arg in filewrite['arguments']:
                if arg['name'] == 'HandleName':
                    filename = arg['value']
            if filename is not None:
                if (self._search_re(filename, self.ignorepaths) and
                        not self._search_re(filename, self.includepaths)):
                    continue
                filenodename = self._add_file(filename)
                # Get a sequential number for the event...
                nextid = len(self.nodemetadata)
                fwnodename = "FILE WRITE {0}".format(nextid)
                self.nodemetadata[fwnodename] = dict()
                self.nodemetadata[fwnodename]['file'] = filename
                self.nodemetadata[fwnodename]['node_type'] = 'FILEWRITE'
                self.nodemetadata[fwnodename]['timestamp'] =\
                    filewrite['timestamp']
                self.digraph.add_node(fwnodename, type='FILEWRITE')

                self.digraph.add_edge(node, fwnodename)
                self.digraph.add_edge(fwnodename, filenodename)

    def _add_file_reads(self, node, calls):
        """
        Internal function that adds the file reads in the calls for
        the PID node.

        :param node:  PID node name.
        :param calls:  Calls for node.
        :returns: Nothing.
        """
        filereads = calls[(calls['api'] == 'NtReadFile') &
                          (calls['status'] == True)]

        for i, fileread in filereads.iterrows():
            filename = None
            for arg in fileread['arguments']:
                if arg['name'] == 'HandleName':
                    filename = arg['value']
            if filename is not None:
                if (self._search_re(filename, self.ignorepaths) and
                        not self._search_re(filename, self.includepaths)):
                    continue
                filenodename = self._add_file(filename)
                # Get a sequential number for the event...
                nextid = len(self.nodemetadata)
                frnodename = "FILE READ {0}".format(nextid)
                self.nodemetadata[frnodename] = dict()
                self.nodemetadata[frnodename]['file'] = filename
                self.nodemetadata[frnodename]['node_type'] = 'FILEREAD'
                self.nodemetadata[frnodename]['timestamp'] =\
                    fileread['timestamp']
                self.digraph.add_node(frnodename, type='FILEREAD')

                self.digraph.add_edge(node, frnodename)
                self.digraph.add_edge(frnodename, filenodename)

    def _add_network_activity(self):
        """
        Internal function that adds network data to the graph.
        Assumes processes have already been plotted.

        :returns:  Nothin.
        """
        self.domains =\
            pandas.DataFrame(self.jsonreportdata['network']['domains'])
        self.dns =\
            pandas.DataFrame(self.jsonreportdata['network']['dns'])

        for i, dns in self.dns.iterrows():
            self.dns.ix[i]['answers'] =\
                pandas.DataFrame(self.dns.ix[i]['answers'])

        metadata = self.nodemetadata.copy()
        for node in metadata:
            if metadata[node]['node_type'] == 'PID':
                if 'calls' in metadata[node]:
                    calls = metadata[node]['calls']

                    # Get DNS lookups...
                    self._add_dns_lookups(node, calls)
                    # Add socket activity...
                    self._add_sockets(node, calls)
                    # Add internet activity outside sockets...
                    self._add_internet(node, calls)
                    # Resolve...
                    self._add_resolve_hosts()

    def _add_internet(self, node, calls):
        """
        Internal function to add internet activity outside
        socket activity.

        :param node: The node name for the calls.
        :param calls:  A pandas.DataFrame of process calls
            for node.
        :returns: Nothing.
        """
        self._add_internet_url(node, calls)
        self._add_internet_server_connect(node, calls)
        self._add_internet_ip_connect(node, calls)

    def _add_internet_ip_connect(self, node, calls):
        """
        Internal function to add ip connect activity.

        :param node:  The node name for the calls.
        :param calls:  A pandas.DataFrame of process calls
            for node.
        :returns: Nothing.
        """
        ips = calls[(calls['api'] == 'ConnectEx')]

        for i, ip in ips.iterrows():
            destip = None

            for arg in ip['arguments']:
                if arg['name'] == 'ip':
                    destip = arg['value']
                if arg['name'] == 'port':
                    destport = arg['value']

            if destip is not None:
                ipnodename = self._add_ip(destip)
                # Get a sequential number for the event...
                nextid = len(self.nodemetadata)
                connnodename = "IP CONNECT {0}".format(nextid)
                self.nodemetadata[connnodename] = dict()
                self.nodemetadata[connnodename]['ip'] = destip
                self.nodemetadata[connnodename]['port'] = destport
                self.nodemetadata[connnodename]['node_type'] = 'IPCONNECT'
                self.nodemetadata[connnodename]['timestamp'] =\
                    ip['timestamp']
                self.digraph.add_node(connnodename, type='IPCONNECT')

                self.digraph.add_edge(node, connnodename)
                self.digraph.add_edge(connnodename, ipnodename)

    def _add_internet_server_connect(self, node, calls):
        """
        Internal function to add internet server connect activity.

        :param node:  The node name for the calls.
        :param calls:  A pandas.DataFrame of process calls
            for node.
        :returns: Nothing.
        """
        servers = calls[((calls['api'] == 'InternetConnectA') |
                        (calls['api'] == 'InternetConnectW')) &
                        (calls['status'] == True)]

        for i, server in servers.iterrows():
            destserver = None

            for arg in server['arguments']:
                if arg['name'] == 'ServerName':
                    destserver = arg['value']
                if arg['name'] == 'ServerPort':
                    destport = arg['value']

            if destserver is not None:
                servernodename = self._add_host(destserver)
                # Get a sequential number for the event...
                nextid = len(self.nodemetadata)
                connnodename = "SERVER CONNECT {0}".format(nextid)
                self.nodemetadata[connnodename] = dict()
                self.nodemetadata[connnodename]['server'] = destserver
                self.nodemetadata[connnodename]['port'] = destport
                self.nodemetadata[connnodename]['node_type'] = 'SERVERCONNECT'
                self.nodemetadata[connnodename]['timestamp'] =\
                    server['timestamp']
                self.digraph.add_node(connnodename, type='SERVERCONNECT')

                self.digraph.add_edge(node, connnodename)
                self.digraph.add_edge(connnodename, servernodename)

    def _add_internet_url(self, node, calls):
        """
        Internal function to add internet url activity.

        :param node:  The node name for the calls.
        :param calls:  A pandas.DataFrame of process calls
            for node.
        :returns: Nothing.
        """
        urls = calls[((calls['api'] == 'InternetOpenUrlW') |
                     (calls['api'] == 'InternetOpenUrlA')) &
                     (calls['status'] == True)]

        for i, url in urls.iterrows():
            desturl = None

            for arg in url['arguments']:
                if arg['name'] == 'URL':
                    desturl = arg['value']

            if desturl is not None:
                urlnodename = self._add_url(desturl)
                self.digraph.add_edge(node, urlnodename)

    def _add_resolve_hosts(self):
        """
        Internal function to resolve hostnames to IPs.

        :returns:  Nothing.
        """
        digraphcopy = self.digraph.copy()

        for node in digraphcopy:
            if digraphcopy.node[node]['type'] == 'HOST':
                hostname = self.nodemetadata[node]['host']
                dns = self.dns[self.dns['request'] == hostname]

                for i, d in dns.iterrows():
                    for j, a in d['answers'].iterrows():
                        if a['type'] == 'A':
                            ipnodename = self._add_ip(a['data'])
                            self.digraph.add_edge(node, ipnodename)

    def _add_dns_lookups(self, node, calls):
        """
        Internal function to add DNS lookups to the graph.

        :param node: The node name for the calls.
        :param calls:  A pandas.DataFrame of process calls.
        :returns:  Nothing.
        """
        dnslookups = calls[calls['api'] == 'gethostbyname']

        for i, lookup in dnslookups.iterrows():
            hostname = None

            for arg in lookup['arguments']:
                if arg['name'] == 'Name':
                    hostname = arg['value']
                    break

            if hostname is not None:
                hostnodename = self._add_host(hostname)
                self.digraph.add_edge(node, hostnodename)

                dns = self.dns[(self.dns['request'] == hostname)]

                for i, d in dns.iterrows():
                    for j, a in d['answers'].iterrows():
                        if a['type'] == 'A':
                            ipnodename = self._add_ip(a['data'])
                            self.digraph.add_edge(hostnodename, ipnodename)

                # ips = self.domains[self.domains['domain'] == hostname]

                # for j, ip in ips.iterrows():
                #     ipnodename = self._add_ip(ip['ip'])
                #     self.digraph.add_edge(hostnodename, ipnodename)

    def _add_host(self, host):
        """
        Internal function to add a host if it does not exist.

        :param host: Host name.
        :returns: Node name for the host.
        """
        hostnodename = "HOST {0}".format(host)
        if hostnodename not in self.nodemetadata:
            self.nodemetadata[hostnodename] = dict()
            self.nodemetadata[hostnodename]['node_type'] = 'HOST'
            self.nodemetadata[hostnodename]['host'] = host
            self.digraph.add_node(hostnodename, type='HOST')

        return hostnodename

    def _add_ip(self, ip):
        """
        Internal function to add an IP if it does not exist.

        :param ip: IP address.
        :returns: Node name for the IP address.
        """
        ipnodename = '"IP {0}"'.format(ip)
        if ipnodename not in self.nodemetadata:
            self.nodemetadata[ipnodename] = dict()
            self.nodemetadata[ipnodename]['node_type'] = 'IP'
            self.nodemetadata[ipnodename]['ip'] = ip
            self.digraph.add_node(ipnodename, type='IP')

        return ipnodename

    def _add_file(self, filename):
        """
        Internal function to add a file if it does not exist.

        :param ip: File path.
        :returns: Node name for the file.
        """
        origfilename = filename
        filename = filename.replace('\\', '\\\\')
        filenodename = '"FILE {0}"'.format(filename)
        if filenodename not in self.nodemetadata:
            self.nodemetadata[filenodename] = dict()
            self.nodemetadata[filenodename]['node_type'] = 'FILE'
            self.nodemetadata[filenodename]['file'] = origfilename
            self.digraph.add_node(filenodename, type='FILE')

        return filenodename

    def _add_reg(self, registry):
        """
        Internal function to add a registry if it does not exsit.

        :param registry:  Registry
        :returns: Node name for the registry.
        """
        origregistry = registry
        registry = registry.replace('\\', '\\\\')
        regnodename = '"REGISTRY {0}"'.format(registry)
        if regnodename not in self.nodemetadata:
            nextid = len(self.nodemetadata)
            newregnodename = 'REGISTRY {0}'.format(nextid)
            self.nodemetadata[newregnodename] = dict()
            self.nodemetadata[newregnodename]['link'] = regnodename
            self.nodemetadata[regnodename] = dict()
            self.nodemetadata[regnodename]['node_type'] = 'REGISTRY'
            self.nodemetadata[regnodename]['registry'] = origregistry
            self.nodemetadata[regnodename]['link'] = newregnodename
            self.digraph.add_node(newregnodename, type='REGISTRY')
        else:
            newregnodename = self.nodemetadata[regnodename]['link']

        return newregnodename

    def _add_url(self, url):
        """
        Internal function to add a URL if it does not exist.

        :param url:  URL
        :returns: Node name for the URL.
        """
        origurl = url
        urlnodename = '"URL {0}"'.format(url)
        if urlnodename not in self.nodemetadata:
            self.nodemetadata[urlnodename] = dict()
            self.nodemetadata[urlnodename]['node_type'] = 'URL'
            self.nodemetadata[urlnodename]['url'] = origurl
            self.digraph.add_node(urlnodename, type='URL')

        return urlnodename

    def _add_sockets(self, node, calls):
        """
        Internal function to add Sockets to the graph.

        :param node:  The node name for the calls.
        :param calls:  A pandas.DataFrame of process calls.
        :returns: Nothing.
        """
        sockets = calls[calls['api'] == 'socket']

        for i, sock in sockets.iterrows():
            socketid = None
            socketproto = None

            for arg in sock['arguments']:
                if arg['name'] == 'socket':
                    socketid = arg['value']
                if arg['name'] == 'protocol':
                    if int(arg['value']) in self.IPProto:
                        socketproto = self.IPProto[int(arg['value'])]
                    else:
                        socketproto = arg['value']

            if socketid is not None:
                # Get a sequential number for the event...
                # Sockets can be reused...
                nextid = len(self.nodemetadata)

                socketname = 'SOCKET {0}'.format(nextid)
                self.digraph.add_node(socketname, type='SOCKET')
                self.nodemetadata[socketname] = dict()
                self.nodemetadata[socketname]['node_type'] = 'SOCKET'
                self.nodemetadata[socketname]['socket'] = socketid
                self.nodemetadata[socketname]['protocol'] = socketproto
                self.nodemetadata[socketname]['opentime'] =\
                    sock['timestamp']

                closesockets = calls[(calls['api'] == 'closesocket') &
                                     (calls['timestamp'] > sock['timestamp'])]
                try:
                    closetime = next(closesockets.iterrows())[1]['timestamp']
                except StopIteration:
                    closetime = None
                self.nodemetadata[socketname]['closetime'] = closetime

                self.digraph.add_edge(node, socketname)

                self._add_tcp_connects(socketname, calls, socketid,
                                       sock['timestamp'], closetime)

    def _add_tcp_connects(self, node, calls, socketid, opentime, closetime):
        """
        Internal function to add TCP connections to the graph.

        :param node:  The socket node name for the calls.
        :param calls:  A pandas.DataFrame of process calls.
        :param socketid:  The socket opened for these connections.
        :param opentime:  The time the socket opened.
        :param closetime:  The time the socket closed.
        :returns: Nothing.
        """
        if closetime is not None:
            tcpconnects = calls[(calls['api'] == 'connect') &
                                (calls['timestamp'] >= opentime) &
                                (calls['timestamp'] <= closetime)]
        else:
            tcpconnects = calls[(calls['api'] == 'connect') &
                                (calls['timestamp'] >= opentime)]

        for i, tcpconnect in tcpconnects.iterrows():
            PlotConnect = False
            for arg in tcpconnect['arguments']:
                if (arg['name'] == 'socket' and
                        arg['value'] == socketid):
                    PlotConnect = True

            if PlotConnect is True:
                ipaddr = None
                socketid = None
                port = None
                for arg in tcpconnect['arguments']:
                    if arg['name'] == 'ip':
                        ipaddr = arg['value']
                    if arg['name'] == 'socket':
                        socketid = arg['value']
                    if arg['name'] == 'port':
                        port = arg['value']

                if ipaddr is not None:
                    ipnodename = self._add_ip(ipaddr)

                    # Get a sequential number for the event...
                    nextid = len(self.nodemetadata)

                    connnodename = 'TCP CONNECT {0}'.format(nextid)
                    self.digraph.add_node(connnodename, type='TCPCONNECT')
                    self.nodemetadata[connnodename] = dict()
                    self.nodemetadata[connnodename]['node_type'] =\
                        "TCPCONNECT"
                    self.nodemetadata[connnodename]['timestamp'] =\
                        tcpconnect['timestamp']
                    self.nodemetadata[connnodename]['ip'] = ipaddr
                    self.nodemetadata[connnodename]['socket'] = socketid
                    self.nodemetadata[connnodename]['port'] = port

                    # Connect them up...
                    self.digraph.add_edge(node, connnodename)
                    self.digraph.add_edge(connnodename, ipnodename)

    def _add_registry_activity(self):
        """
        Internal function that adds registry data to the graph.
        Assumes processes have already been plotted.

        :returns:  Nothing.
        """
        metadata = self.nodemetadata.copy()
        for node in metadata:
            if metadata[node]['node_type'] == 'PID':
                if 'calls' in metadata[node]:
                    calls = metadata[node]['calls']

                    # Get registry writes...
                    if self.plotregistrywrites is True:
                        self._add_registry_writes(node, calls)

                    if self.plotregistrydeletes is True:
                        self._add_registry_deletes(node, calls)

                    if self.plotregistrycreates is True:
                        self._add_registry_creates(node, calls)

                    if self.plotregistryreads is True:
                        self._add_registry_reads(node, calls)

    def _add_registry_writes(self, node, calls):
        """
        Internal function that adds registry writes to the graph.

        :param node:  The PID node name for the calls.
        :param calls:  The api calls.
        :returns:  Nothing.
        """
        regwrites = calls[((calls['api'] == 'RegSetValueExA') |
                          (calls['api'] == 'RegSetValueExW') |
                          (calls['api'] == 'NtSetValueKey')) &
                          (calls['status'] == True)]

        for i, regwrite in regwrites.iterrows():
            regname = None
            for arg in regwrite['arguments']:
                if arg['name'] == 'FullName':
                    regname = arg['value']
                if arg['name'] == 'Buffer':
                    regbuff = arg['value']
            if regname is not None:
                if (self._search_re(regname, self.ignorepaths) and
                        not self._search_re(regname, self.includepaths)):
                    continue
                regnodename = self._add_reg(regname)
                # Get a sequential number for the event...
                nextid = len(self.nodemetadata)
                rwnodename = "REGISTRY WRITE {0}".format(nextid)
                self.nodemetadata[rwnodename] = dict()
                self.nodemetadata[rwnodename]['registry'] = regname
                self.nodemetadata[rwnodename]['node_type'] = 'REGISTRYWRITE'
                self.nodemetadata[rwnodename]['timestamp'] =\
                    regwrite['timestamp']
                self.nodemetadata[rwnodename]['buffer'] = regbuff
                self.digraph.add_node(rwnodename, type='REGISTRYWRITE')

                self.digraph.add_edge(node, rwnodename)
                self.digraph.add_edge(rwnodename, regnodename)

    def _add_registry_deletes(self, node, calls):
        """
        Internal function that adds registry deletes to the graph.

        :param node:  The PID node name for the calls.
        :param calls:  The api calls.
        :returns:  Nothing.
        """
        regdeletes = calls[((calls['api'] == 'RegDeleteValueA') |
                           (calls['api'] == 'RegDeleteValueW') |
                           (calls['api'] == 'NtDeleteKey')) &
                           (calls['status'] == True)]

        for i, regdelete in regdeletes.iterrows():
            regname = None
            for arg in regdelete['arguments']:
                if arg['name'] == 'FullName':
                    regname = arg['value']
            if regname is not None:
                if (self._search_re(regname, self.ignorepaths) and
                        not self._search_re(regname, self.includepaths)):
                    continue
                regnodename = self._add_reg(regname)
                # Get a sequential number for the event...
                nextid = len(self.nodemetadata)
                rdnodename = "REGISTRY DELETE {0}".format(nextid)
                self.nodemetadata[rdnodename] = dict()
                self.nodemetadata[rdnodename]['registry'] = regname
                self.nodemetadata[rdnodename]['node_type'] = 'REGISTRYDELETE'
                self.nodemetadata[rdnodename]['timestamp'] =\
                    regdelete['timestamp']
                self.digraph.add_node(rdnodename, type='REGISTRYDELETE')

                self.digraph.add_edge(node, rdnodename)
                self.digraph.add_edge(rdnodename, regnodename)

    def _add_registry_creates(self, node, calls):
        """
        Internal function that adds registry creates to the graph.

        :param node:  The PID node name for the calls.
        :param calls:  The api calls.
        :returns:  Nothing.
        """
        regcreates = calls[((calls['api'] == 'RegCreateKeyExA') |
                           (calls['api'] == 'RegCreateKeyExW') |
                           (calls['api'] == 'NtCreateKey')) &
                           (calls['status'] == True)]

        for i, regcreate in regcreates.iterrows():
            regname = None
            for arg in regcreate['arguments']:
                if arg['name'] == 'FullName':
                    regname = arg['value']
            if regname is not None:
                if (self._search_re(regname, self.ignorepaths) and
                        not self._search_re(regname, self.includepaths)):
                    continue
                regnodename = self._add_reg(regname)
                # Get a sequential number for the event...
                nextid = len(self.nodemetadata)
                rcnodename = "REGISTRY CREATE {0}".format(nextid)
                self.nodemetadata[rcnodename] = dict()
                self.nodemetadata[rcnodename]['registry'] = regname
                self.nodemetadata[rcnodename]['node_type'] = 'REGISTRYCREATE'
                self.nodemetadata[rcnodename]['timestamp'] =\
                    regcreate['timestamp']
                self.digraph.add_node(rcnodename, type='REGISTRYCREATE')

                self.digraph.add_edge(node, rcnodename)
                self.digraph.add_edge(rcnodename, regnodename)

    def _add_registry_reads(self, node, calls):
        """
        Internal function that adds registry reads to the graph.

        :param node:  The PID node name for the calls.
        :param calls:  The api calls.
        :returns:  Nothing.
        """
        regreads = calls[((calls['api'] == 'RegQueryValueExA') |
                         (calls['api'] == 'RegQueryValueExW') |
                         (calls['api'] == 'NtQueryValueKey')) &
                         (calls['status'] == True)]

        for i, regread in regreads.iterrows():
            regname = None
            for arg in regread['arguments']:
                if arg['name'] == 'FullName':
                    regname = arg['value']
            if regname is not None:
                if (self._search_re(regname, self.ignorepaths) and
                        not self._search_re(regname, self.includepaths)):
                    continue
                regnodename = self._add_reg(regname)
                # Get a sequential number for the event...
                nextid = len(self.nodemetadata)
                rrnodename = "REGISTRY READ {0}".format(nextid)
                self.nodemetadata[rrnodename] = dict()
                self.nodemetadata[rrnodename]['registry'] = regname
                self.nodemetadata[rrnodename]['node_type'] = 'REGISTRYREAD'
                self.nodemetadata[rrnodename]['timestamp'] =\
                    regread['timestamp']
                self.digraph.add_node(rrnodename, type='REGISTRYREAD')

                self.digraph.add_edge(node, rrnodename)
                self.digraph.add_edge(rrnodename, regnodename)

    def _create_positions_digraph(self):
        """
        Internal function to create the positions of the graph.

        :returns: Nothing.
        """

        # Create the positions...
        if self.graphvizprog is None:
            #  self.pos = networkx.fruchterman_reingold_layout(self.digraph)
            self.pos = networkx.spring_layout(self.digraph)
            # self.pos = networkx.circular_layout(self.digraph)
            # self.pos = networkx.shell_layout(self.digraph)
            # self.pos = networkx.spectral_layout(self.digraph)
        else:
            self.pos = \
                networkx.drawing.nx_pydot.graphviz_layout(
                    self.digraph, prog=self.graphvizprog,
                    root=self.rootpid)

    def _generategraph(self):
        """
        Internal function to create the output data for plotly.

        :returns: The data that can be plotted with plotly scatter
            plots.
        """

        # Node coordinates...
        ProcessX = []
        ProcessY = []
        HostX = []
        HostY = []
        IPX = []
        IPY = []
        SocketX = []
        SocketY = []
        TCPConnectX = []
        TCPConnectY = []
        FileX = []
        FileY = []
        FileCreateX = []
        FileCreateY = []
        FileWriteX = []
        FileWriteY = []
        FileCopyX = []
        FileCopyY = []
        FileDeleteX = []
        FileDeleteY = []
        FileMoveX = []
        FileMoveY = []
        FileReadX = []
        FileReadY = []
        RegistryX = []
        RegistryY = []
        RegistryWriteX = []
        RegistryWriteY = []
        RegistryDeleteX = []
        RegistryDeleteY = []
        RegistryCreateX = []
        RegistryCreateY = []
        RegistryReadX = []
        RegistryReadY = []
        URLX = []
        URLY = []
        ServerX = []
        ServerY = []
        IPConnX = []
        IPConnY = []

        # Edge coordinates...
        ProcessXe = []
        ProcessYe = []
        GetNameXe = []
        GetNameYe = []
        DNSXe = []
        DNSYe = []
        SocketXe = []
        SocketYe = []
        TCPConnectXe = []
        TCPConnectYe = []
        FileCreateXe = []
        FileCreateYe = []
        LoadImageXe = []
        LoadImageYe = []
        FileWriteXe = []
        FileWriteYe = []
        FileCopyXe = []
        FileCopyYe = []
        FileDeleteXe = []
        FileDeleteYe = []
        FileMoveXe = []
        FileMoveYe = []
        FileReadXe = []
        FileReadYe = []
        RegistryWriteXe = []
        RegistryWriteYe = []
        RegistryDeleteXe = []
        RegistryDeleteYe = []
        RegistryCreateXe = []
        RegistryCreateYe = []
        RegistryReadXe = []
        RegistryReadYe = []
        URLXe = []
        URLYe = []
        ServerXe = []
        ServerYe = []
        IPConnXe = []
        IPConnYe = []

        # Hover Text...
        proctxt = []
        hosttxt = []
        iptxt = []
        sockettxt = []
        tcpconnecttxt = []
        filetxt = []
        filecreatetxt = []
        filewritetxt = []
        filecopytxt = []
        filedeletetxt = []
        filemovetxt = []
        filereadtxt = []
        registrytxt = []
        registrywritetxt = []
        registrydeletetxt = []
        registrycreatetxt = []
        registryreadtxt = []
        urltxt = []
        servertxt = []
        ipconntxt = []

        # Traverse nodes...
        for node in self.digraph:
            if self.digraph.node[node]['type'] == 'PID':
                ProcessX.append(self.pos[node][0])
                ProcessY.append(self.pos[node][1])
                if 'cmdline' in self.nodemetadata[node]:
                    cmdline = self.nodemetadata[node]['cmdline']
                else:
                    cmdline = "Not Available"
                proctxt.append(
                    "PID: {0}<br>"
                    "Path: {1}<br>"
                    "Command Line: {2}<br>"
                    "Parent PID: {3}<br>"
                    "First Seen: {4}"
                    .format(
                        self.nodemetadata[node]['pid'],
                        self.nodemetadata[node]['module_path'],
                        cmdline,
                        self.nodemetadata[node]['parent_id'],
                        self.nodemetadata[node]['first_seen']
                        )
                               )
            if self.digraph.node[node]['type'] == 'HOST':
                HostX.append(self.pos[node][0])
                HostY.append(self.pos[node][1])
                hosttxt.append(
                    "HOST: {0}"
                    .format(
                        self.nodemetadata[node]['host']
                        )
                               )
            if self.digraph.node[node]['type'] == 'SERVERCONNECT':
                ServerX.append(self.pos[node][0])
                ServerY.append(self.pos[node][1])
                servertxt.append(
                    "Server Connect: {0}<br>"
                    "Port: {1}<br>"
                    "Time: {2}"
                    .format(
                        self.nodemetadata[node]['server'],
                        self.nodemetadata[node]['port'],
                        self.nodemetadata[node]['timestamp']
                        )
                               )
            if self.digraph.node[node]['type'] == 'IPCONNECT':
                IPConnX.append(self.pos[node][0])
                IPConnY.append(self.pos[node][1])
                ipconntxt.append(
                    "IP Connect: {0}<br>"
                    "Port: {1}<br>"
                    "Time: {2}"
                    .format(
                        self.nodemetadata[node]['ip'],
                        self.nodemetadata[node]['port'],
                        self.nodemetadata[node]['timestamp']
                        )
                               )
            if self.digraph.node[node]['type'] == 'IP':
                IPX.append(self.pos[node][0])
                IPY.append(self.pos[node][1])
                iptxt.append(
                    "IP: {0}"
                    .format(
                        self.nodemetadata[node]['ip']
                        )
                               )
            if self.digraph.node[node]['type'] == 'SOCKET':
                SocketX.append(self.pos[node][0])
                SocketY.append(self.pos[node][1])
                sockettxt.append(
                    "Socket: {0}<br>"
                    "Protocol: {1}<br>"
                    "Open Time: {2}<br>"
                    "Close TIme: {3}"
                    .format(
                        self.nodemetadata[node]['socket'],
                        self.nodemetadata[node]['protocol'],
                        self.nodemetadata[node]['opentime'],
                        self.nodemetadata[node]['closetime']
                        )
                               )
            if self.digraph.node[node]['type'] == 'TCPCONNECT':
                TCPConnectX.append(self.pos[node][0])
                TCPConnectY.append(self.pos[node][1])
                tcpconnecttxt.append(
                    "TCP Connect:<br>"
                    "IP: {0}<br>"
                    "Port: {1}<br>"
                    "Socket: {2}<br>"
                    "Time: {3}"
                    .format(
                        self.nodemetadata[node]['ip'],
                        self.nodemetadata[node]['port'],
                        self.nodemetadata[node]['socket'],
                        self.nodemetadata[node]['timestamp']
                        )
                               )
            if self.digraph.node[node]['type'] == 'FILE':
                FileX.append(self.pos[node][0])
                FileY.append(self.pos[node][1])
                filetxt.append(
                    "File: {0}"
                    .format(
                        self.nodemetadata[node]['file']
                        )
                               )
            if self.digraph.node[node]['type'] == 'FILECREATE':
                FileCreateX.append(self.pos[node][0])
                FileCreateY.append(self.pos[node][1])
                filecreatetxt.append(
                    "File Create: {0}<br>"
                    "Existed Before: {1}<br>"
                    "Desired Access: {2}<br>"
                    "Create Disposition: {3}<br>"
                    "File Atributes: {4}<br>"
                    "Time: {5}"
                    .format(
                        self.nodemetadata[node]['file'],
                        self.nodemetadata[node]['existedbefore'],
                        self.nodemetadata[node]['desiredaccess'],
                        self.nodemetadata[node]['createdisposition'],
                        self.nodemetadata[node]['fileattribtes'],
                        self.nodemetadata[node]['timestamp']
                        )
                               )
            if self.digraph.node[node]['type'] == 'FILEWRITE':
                FileWriteX.append(self.pos[node][0])
                FileWriteY.append(self.pos[node][1])
                filewritetxt.append(
                    "File Write: {0}<br>"
                    "Time: {1}"
                    .format(
                        self.nodemetadata[node]['file'],
                        self.nodemetadata[node]['timestamp']
                        )
                               )
            if self.digraph.node[node]['type'] == 'FILECOPY':
                FileCopyX.append(self.pos[node][0])
                FileCopyY.append(self.pos[node][1])
                filecopytxt.append(
                    "File Copy:<br>"
                    "Existing File: {0}<br>"
                    "New File: {1}<br>"
                    "Existed Before: {2}<br>"
                    "Time: {3}"
                    .format(
                        self.nodemetadata[node]['existingfile'],
                        self.nodemetadata[node]['newfile'],
                        self.nodemetadata[node]['existedbefore'],
                        self.nodemetadata[node]['timestamp']
                        )
                               )
            if self.digraph.node[node]['type'] == 'FILEDELETE':
                FileDeleteX.append(self.pos[node][0])
                FileDeleteY.append(self.pos[node][1])
                filedeletetxt.append(
                    "File Delete: {0}<br>"
                    "Time: {1}"
                    .format(
                        self.nodemetadata[node]['file'],
                        self.nodemetadata[node]['timestamp']
                        )
                               )
            if self.digraph.node[node]['type'] == 'FILEMOVE':
                FileMoveX.append(self.pos[node][0])
                FileMoveY.append(self.pos[node][1])
                filemovetxt.append(
                    "File Move:<br>"
                    "Existing File: {0}<br>"
                    "New File: {1}<br>"
                    "Time: {2}"
                    .format(
                        self.nodemetadata[node]['existingfile'],
                        self.nodemetadata[node]['newfile'],
                        self.nodemetadata[node]['timestamp']
                        )
                               )
            if self.digraph.node[node]['type'] == 'FILEREAD':
                FileReadX.append(self.pos[node][0])
                FileReadY.append(self.pos[node][1])
                filereadtxt.append(
                    "File Read: {0}<br>"
                    "Time: {1}"
                    .format(
                        self.nodemetadata[node]['file'],
                        self.nodemetadata[node]['timestamp']
                        )
                               )
            if self.digraph.node[node]['type'] == 'REGISTRY':
                RegistryX.append(self.pos[node][0])
                RegistryY.append(self.pos[node][1])
                newreg = self.nodemetadata[node]['link']
                registrytxt.append(
                    "Registry: {0}"
                    .format(
                        self.nodemetadata[newreg]['registry']
                        )
                               )
            if self.digraph.node[node]['type'] == 'REGISTRYWRITE':
                RegistryWriteX.append(self.pos[node][0])
                RegistryWriteY.append(self.pos[node][1])
                registrywritetxt.append(
                    "Registry Write: {0}<br>"
                    "Buffer: {1}<br>"
                    "Time: {2}"
                    .format(
                        self.nodemetadata[node]['registry'],
                        self.nodemetadata[node]['buffer'],
                        self.nodemetadata[node]['timestamp']
                        )
                               )
            if self.digraph.node[node]['type'] == 'REGISTRYDELETE':
                RegistryDeleteX.append(self.pos[node][0])
                RegistryDeleteY.append(self.pos[node][1])
                registrydeletetxt.append(
                    "Registry Delete: {0}<br>"
                    "Time: {1}"
                    .format(
                        self.nodemetadata[node]['registry'],
                        self.nodemetadata[node]['timestamp']
                        )
                               )
            if self.digraph.node[node]['type'] == 'REGISTRYCREATE':
                RegistryCreateX.append(self.pos[node][0])
                RegistryCreateY.append(self.pos[node][1])
                registrycreatetxt.append(
                    "Registry Create: {0}<br>"
                    "Time: {1}"
                    .format(
                        self.nodemetadata[node]['registry'],
                        self.nodemetadata[node]['timestamp']
                        )
                               )
            if self.digraph.node[node]['type'] == 'REGISTRYREAD':
                RegistryReadX.append(self.pos[node][0])
                RegistryReadY.append(self.pos[node][1])
                registryreadtxt.append(
                    "Registry Read: {0}<br>"
                    "Time: {1}"
                    .format(
                        self.nodemetadata[node]['registry'],
                        self.nodemetadata[node]['timestamp']
                        )
                               )
            if self.digraph.node[node]['type'] == 'URL':
                URLX.append(self.pos[node][0])
                URLY.append(self.pos[node][1])
                urltxt.append(
                    "URL: {0}"
                    .format(
                        self.nodemetadata[node]['url']
                        )
                               )

        # Traverse edges...
        for edge in self.digraph.edges():
            if (self.digraph.node[edge[0]]['type'] == 'PID' and
                    self.digraph.node[edge[1]]['type'] == 'PID'):
                ProcessXe.append(self.pos[edge[0]][0])
                ProcessXe.append(self.pos[edge[1]][0])
                ProcessXe.append(None)
                ProcessYe.append(self.pos[edge[0]][1])
                ProcessYe.append(self.pos[edge[1]][1])
                ProcessYe.append(None)
            if (self.digraph.node[edge[0]]['type'] == 'PID' and
                    self.digraph.node[edge[1]]['type'] == 'HOST'):
                GetNameXe.append(self.pos[edge[0]][0])
                GetNameXe.append(self.pos[edge[1]][0])
                GetNameXe.append(None)
                GetNameYe.append(self.pos[edge[0]][1])
                GetNameYe.append(self.pos[edge[1]][1])
                GetNameYe.append(None)
            if ((self.digraph.node[edge[0]]['type'] == 'PID' and
                self.digraph.node[edge[1]]['type'] == 'SERVERCONNECT') or
                (self.digraph.node[edge[0]]['type'] == 'SERVERCONNECT' and
                    self.digraph.node[edge[1]]['type'] == 'HOST')):
                ServerXe.append(self.pos[edge[0]][0])
                ServerXe.append(self.pos[edge[1]][0])
                ServerXe.append(None)
                ServerYe.append(self.pos[edge[0]][1])
                ServerYe.append(self.pos[edge[1]][1])
                ServerYe.append(None)
            if ((self.digraph.node[edge[0]]['type'] == 'PID' and
                self.digraph.node[edge[1]]['type'] == 'IPCONNECT') or
                (self.digraph.node[edge[0]]['type'] == 'IPCONNECT' and
                    self.digraph.node[edge[1]]['type'] == 'IP')):
                IPConnXe.append(self.pos[edge[0]][0])
                IPConnXe.append(self.pos[edge[1]][0])
                IPConnXe.append(None)
                IPConnYe.append(self.pos[edge[0]][1])
                IPConnYe.append(self.pos[edge[1]][1])
                IPConnYe.append(None)
            if (self.digraph.node[edge[0]]['type'] == 'HOST' and
                    self.digraph.node[edge[1]]['type'] == 'IP'):
                DNSXe.append(self.pos[edge[0]][0])
                DNSXe.append(self.pos[edge[1]][0])
                DNSXe.append(None)
                DNSYe.append(self.pos[edge[0]][1])
                DNSYe.append(self.pos[edge[1]][1])
                DNSYe.append(None)
            if (self.digraph.node[edge[0]]['type'] == 'PID' and
                    self.digraph.node[edge[1]]['type'] == 'SOCKET'):
                SocketXe.append(self.pos[edge[0]][0])
                SocketXe.append(self.pos[edge[1]][0])
                SocketXe.append(None)
                SocketYe.append(self.pos[edge[0]][1])
                SocketYe.append(self.pos[edge[1]][1])
                SocketYe.append(None)
            if ((self.digraph.node[edge[0]]['type'] == 'SOCKET' and
                self.digraph.node[edge[1]]['type'] == 'TCPCONNECT') or
                (self.digraph.node[edge[0]]['type'] == 'TCPCONNECT' and
                    self.digraph.node[edge[1]]['type'] == 'IP')):
                TCPConnectXe.append(self.pos[edge[0]][0])
                TCPConnectXe.append(self.pos[edge[1]][0])
                TCPConnectXe.append(None)
                TCPConnectYe.append(self.pos[edge[0]][1])
                TCPConnectYe.append(self.pos[edge[1]][1])
                TCPConnectYe.append(None)
            if ((self.digraph.node[edge[0]]['type'] == 'PID' and
                self.digraph.node[edge[1]]['type'] == 'FILECREATE') or
                (self.digraph.node[edge[0]]['type'] == 'FILECREATE' and
                    self.digraph.node[edge[1]]['type'] == 'FILE')):
                FileCreateXe.append(self.pos[edge[0]][0])
                FileCreateXe.append(self.pos[edge[1]][0])
                FileCreateXe.append(None)
                FileCreateYe.append(self.pos[edge[0]][1])
                FileCreateYe.append(self.pos[edge[1]][1])
                FileCreateYe.append(None)
            if ((self.digraph.node[edge[0]]['type'] == 'PID' and
                self.digraph.node[edge[1]]['type'] == 'FILEWRITE') or
                (self.digraph.node[edge[0]]['type'] == 'FILEWRITE' and
                    self.digraph.node[edge[1]]['type'] == 'FILE')):
                FileWriteXe.append(self.pos[edge[0]][0])
                FileWriteXe.append(self.pos[edge[1]][0])
                FileWriteXe.append(None)
                FileWriteYe.append(self.pos[edge[0]][1])
                FileWriteYe.append(self.pos[edge[1]][1])
                FileWriteYe.append(None)
            if (self.digraph.node[edge[0]]['type'] == 'FILE' and
                    self.digraph.node[edge[1]]['type'] == 'PID'):
                LoadImageXe.append(self.pos[edge[0]][0])
                LoadImageXe.append(self.pos[edge[1]][0])
                LoadImageXe.append(None)
                LoadImageYe.append(self.pos[edge[0]][1])
                LoadImageYe.append(self.pos[edge[1]][1])
                LoadImageYe.append(None)
            if ((self.digraph.node[edge[0]]['type'] == 'PID' and
                self.digraph.node[edge[1]]['type'] == 'FILECOPY') or
                (self.digraph.node[edge[0]]['type'] == 'FILECOPY' and
                    self.digraph.node[edge[1]]['type'] == 'FILE')):
                FileCopyXe.append(self.pos[edge[0]][0])
                FileCopyXe.append(self.pos[edge[1]][0])
                FileCopyXe.append(None)
                FileCopyYe.append(self.pos[edge[0]][1])
                FileCopyYe.append(self.pos[edge[1]][1])
                FileCopyYe.append(None)
            if ((self.digraph.node[edge[0]]['type'] == 'PID' and
                self.digraph.node[edge[1]]['type'] == 'FILEDELETE') or
                (self.digraph.node[edge[0]]['type'] == 'FILEDELETE' and
                    self.digraph.node[edge[1]]['type'] == 'FILE')):
                FileDeleteXe.append(self.pos[edge[0]][0])
                FileDeleteXe.append(self.pos[edge[1]][0])
                FileDeleteXe.append(None)
                FileDeleteYe.append(self.pos[edge[0]][1])
                FileDeleteYe.append(self.pos[edge[1]][1])
                FileDeleteYe.append(None)
            if ((self.digraph.node[edge[0]]['type'] == 'PID' and
                self.digraph.node[edge[1]]['type'] == 'FILEMOVE') or
                (self.digraph.node[edge[0]]['type'] == 'FILEMOVE' and
                    self.digraph.node[edge[1]]['type'] == 'FILE')):
                FileMoveXe.append(self.pos[edge[0]][0])
                FileMoveXe.append(self.pos[edge[1]][0])
                FileMoveXe.append(None)
                FileMoveYe.append(self.pos[edge[0]][1])
                FileMoveYe.append(self.pos[edge[1]][1])
                FileMoveYe.append(None)
            if ((self.digraph.node[edge[0]]['type'] == 'PID' and
                self.digraph.node[edge[1]]['type'] == 'FILEREAD') or
                (self.digraph.node[edge[0]]['type'] == 'FILEREAD' and
                    self.digraph.node[edge[1]]['type'] == 'FILE')):
                FileReadXe.append(self.pos[edge[0]][0])
                FileReadXe.append(self.pos[edge[1]][0])
                FileReadXe.append(None)
                FileReadYe.append(self.pos[edge[0]][1])
                FileReadYe.append(self.pos[edge[1]][1])
                FileReadYe.append(None)
            if ((self.digraph.node[edge[0]]['type'] == 'PID' and
                self.digraph.node[edge[1]]['type'] == 'REGISTRYWRITE') or
                (self.digraph.node[edge[0]]['type'] == 'REGISTRYWRITE' and
                    self.digraph.node[edge[1]]['type'] == 'REGISTRY')):
                RegistryWriteXe.append(self.pos[edge[0]][0])
                RegistryWriteXe.append(self.pos[edge[1]][0])
                RegistryWriteXe.append(None)
                RegistryWriteYe.append(self.pos[edge[0]][1])
                RegistryWriteYe.append(self.pos[edge[1]][1])
                RegistryWriteYe.append(None)
            if ((self.digraph.node[edge[0]]['type'] == 'PID' and
                self.digraph.node[edge[1]]['type'] == 'REGISTRYDELETE') or
                (self.digraph.node[edge[0]]['type'] == 'REGISTRYDELETE' and
                    self.digraph.node[edge[1]]['type'] == 'REGISTRY')):
                RegistryDeleteXe.append(self.pos[edge[0]][0])
                RegistryDeleteXe.append(self.pos[edge[1]][0])
                RegistryDeleteXe.append(None)
                RegistryDeleteYe.append(self.pos[edge[0]][1])
                RegistryDeleteYe.append(self.pos[edge[1]][1])
                RegistryDeleteYe.append(None)
            if ((self.digraph.node[edge[0]]['type'] == 'PID' and
                self.digraph.node[edge[1]]['type'] == 'REGISTRYCREATE') or
                (self.digraph.node[edge[0]]['type'] == 'REGISTRYCREATE' and
                    self.digraph.node[edge[1]]['type'] == 'REGISTRY')):
                RegistryCreateXe.append(self.pos[edge[0]][0])
                RegistryCreateXe.append(self.pos[edge[1]][0])
                RegistryCreateXe.append(None)
                RegistryCreateYe.append(self.pos[edge[0]][1])
                RegistryCreateYe.append(self.pos[edge[1]][1])
                RegistryCreateYe.append(None)
            if ((self.digraph.node[edge[0]]['type'] == 'PID' and
                self.digraph.node[edge[1]]['type'] == 'REGISTRYREAD') or
                (self.digraph.node[edge[0]]['type'] == 'REGISTRYREAD' and
                    self.digraph.node[edge[1]]['type'] == 'REGISTRY')):
                RegistryReadXe.append(self.pos[edge[0]][0])
                RegistryReadXe.append(self.pos[edge[1]][0])
                RegistryReadXe.append(None)
                RegistryReadYe.append(self.pos[edge[0]][1])
                RegistryReadYe.append(self.pos[edge[1]][1])
                RegistryReadYe.append(None)
            if (self.digraph.node[edge[0]]['type'] == 'PID' and
                self.digraph.node[edge[1]]['type'] == 'URL'):
                URLXe.append(self.pos[edge[0]][0])
                URLXe.append(self.pos[edge[1]][0])
                URLXe.append(None)
                URLYe.append(self.pos[edge[0]][1])
                URLYe.append(self.pos[edge[1]][1])
                URLYe.append(None)

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
                            line=Line(shape='linear',
                                      color='rgb(214,39,20)'),
                            name='Process Start',
                            hoverinfo='none')

        nodes.append(ProcNodes)
        edges.append(ProcEdges)

        # HOSTS...

        marker = Marker(symbol='square', size=10)

        # Create the nodes...
        HostNodes = Scatter(x=HostX,
                            y=HostY,
                            mode='markers',
                            marker=marker,
                            name='Host',
                            text=hosttxt,
                            hoverinfo='text')

        nodes.append(HostNodes)

        # Create the edges for the nodes...
        GetNameEdges = Scatter(x=GetNameXe,
                               y=GetNameYe,
                               mode='lines',
                               line=Line(shape='linear',
                                         color='rgb(174,199,232)'),
                               name='DNS Query',
                               hoverinfo='none')

        edges.append(GetNameEdges)

        # SERVERS...

        marker = Marker(symbol='diamond', size=7)

        # Create the nodes...
        ServerNodes = Scatter(x=ServerX,
                              y=ServerY,
                              mode='markers',
                              marker=marker,
                              name='Server Connections',
                              text=servertxt,
                              hoverinfo='text')

        nodes.append(ServerNodes)

        # Create the edges for the nodes...
        ServerEdges = Scatter(x=ServerXe,
                              y=ServerYe,
                              mode='lines',
                              line=Line(shape='linear'),
                              name='Server Connect',
                              hoverinfo='none')

        edges.append(ServerEdges)

        # IP CONNECTS...

        marker = Marker(symbol='diamond', size=7)

        # Create the nodes...
        IPConnNodes = Scatter(x=IPConnX,
                              y=IPConnY,
                              mode='markers',
                              marker=marker,
                              name='IP Connections',
                              text=ipconntxt,
                              hoverinfo='text')

        nodes.append(IPConnNodes)

        # Create the edges for the nodes...
        IPConnEdges = Scatter(x=IPConnXe,
                              y=IPConnYe,
                              mode='lines',
                              line=Line(shape='linear'),
                              name='IP Connect',
                              hoverinfo='none')

        edges.append(IPConnEdges)

        # IPS...

        marker = Marker(symbol='square', size=10)

        # Create the nodes...
        IPNodes = Scatter(x=IPX,
                          y=IPY,
                          mode='markers',
                          marker=marker,
                          name='IP',
                          text=iptxt,
                          hoverinfo='text')

        nodes.append(IPNodes)

        # Create the edges for the nodes...
        DNSEdges = Scatter(x=DNSXe,
                           y=DNSYe,
                           mode='lines',
                           line=Line(shape='linear',
                                     color='rgb(23,190,207)'),
                           name='DNS Response',
                           hoverinfo='none')

        edges.append(DNSEdges)

        # SOCKETS...

        marker = Marker(symbol='diamond', size=7, color='rgb(277,119,194)')

        # Create the nodes...
        SocketNodes = Scatter(x=SocketX,
                              y=SocketY,
                              mode='markers',
                              marker=marker,
                              name='Socket',
                              text=sockettxt,
                              hoverinfo='text')

        # Create the edges for the nodes...
        SocketEdges = Scatter(x=SocketXe,
                              y=SocketYe,
                              mode='lines',
                              line=Line(shape='linear',
                                        color='rgb(227,119,194)'),
                              name='Create Socket',
                              hoverinfo='none')

        nodes.append(SocketNodes)
        edges.append(SocketEdges)

        # TCP CONNECTS...

        marker = Marker(symbol='diamond', size=7, color='rgb(44,160,44)')

        # Create the nodes...
        TCPConnectNodes = Scatter(x=TCPConnectX,
                                  y=TCPConnectY,
                                  mode='markers',
                                  marker=marker,
                                  name='TCP Connection',
                                  text=tcpconnecttxt,
                                  hoverinfo='text')

        # Create the edges for the nodes...
        TCPConnectEdges = Scatter(x=TCPConnectXe,
                                  y=TCPConnectYe,
                                  mode='lines',
                                  line=Line(shape='linear',
                                            color='rgb(44,160,44)'),
                                  name='TCP Connect',
                                  hoverinfo='none')

        nodes.append(TCPConnectNodes)
        edges.append(TCPConnectEdges)

        # URLS...

        marker = Marker(symbol='square', size=10)

        # Create the nodes...
        URLNodes = Scatter(x=URLX,
                           y=URLY,
                           mode='markers',
                           marker=marker,
                           name='URL',
                           text=urltxt,
                           hoverinfo='text')

        nodes.append(URLNodes)

        # Create the edges for the nodes...
        URLEdges = Scatter(x=URLXe,
                           y=URLYe,
                           mode='lines',
                           line=Line(shape='linear'),
                           name='URL Connect',
                           hoverinfo='none')

        edges.append(URLEdges)

        # FILES...

        marker = Marker(symbol='hexagon', size=10)

        # Create the nodes...
        FileNodes = Scatter(x=FileX,
                            y=FileY,
                            mode='markers',
                            marker=marker,
                            name='File',
                            text=filetxt,
                            hoverinfo='text')

        nodes.append(FileNodes)

        marker = Marker(symbol='triangle-down', size=7,
                        color='rgb(123,102,210)')

        # Create the nodes...
        FileCreateNodes = Scatter(x=FileCreateX,
                                  y=FileCreateY,
                                  mode='markers',
                                  marker=marker,
                                  name='File Create',
                                  text=filecreatetxt,
                                  hoverinfo='text')

        nodes.append(FileCreateNodes)

        # Create the edges for the nodes...
        FileCreateEdges = Scatter(x=FileCreateXe,
                                  y=FileCreateYe,
                                  mode='lines',
                                  line=Line(shape='linear',
                                            color='rgb(123,102,210)'),
                                  name='File Create',
                                  hoverinfo='none')

        edges.append(FileCreateEdges)

        marker = Marker(symbol='triangle-down', size=7,
                        color='rgb(255,187,120)')

        # Create the nodes...
        FileWriteNodes = Scatter(x=FileWriteX,
                                 y=FileWriteY,
                                 mode='markers',
                                 marker=marker,
                                 name='File Write',
                                 text=filewritetxt,
                                 hoverinfo='text')

        nodes.append(FileWriteNodes)

        # Create the edges for the nodes...
        FileWriteEdges = Scatter(x=FileWriteXe,
                                 y=FileWriteYe,
                                 mode='lines',
                                 line=Line(shape='linear',
                                           color='rgb(255,187,120)'),
                                 name='File Write',
                                 hoverinfo='none')

        edges.append(FileWriteEdges)

        marker = Marker(symbol='triangle-down', size=7,
                        color='rgb(65,68,81)')

        # Create the nodes...
        FileCopyNodes = Scatter(x=FileCopyX,
                                y=FileCopyY,
                                mode='markers',
                                marker=marker,
                                name='File Copy',
                                text=filecopytxt,
                                hoverinfo='text')

        nodes.append(FileCopyNodes)

        # Create the edges for the nodes...
        FileCopyEdges = Scatter(x=FileCopyXe,
                                y=FileCopyYe,
                                mode='lines',
                                line=Line(shape='linear',
                                          color='rgb(65,68,81)'),
                                name='File Copy',
                                hoverinfo='none')

        edges.append(FileCopyEdges)

        marker = Marker(symbol='triangle-down', size=7,
                        color='rgb(255,128,14)')

        # Create the nodes...
        FileDeleteNodes = Scatter(x=FileDeleteX,
                                  y=FileDeleteY,
                                  mode='markers',
                                  marker=marker,
                                  name='File Delete',
                                  text=filedeletetxt,
                                  hoverinfo='text')

        nodes.append(FileDeleteNodes)

        # Create the edges for the nodes...
        FileDeleteEdges = Scatter(x=FileDeleteXe,
                                  y=FileDeleteYe,
                                  mode='lines',
                                  line=Line(shape='linear',
                                            color='rgb(255,128,14)'),
                                  name='File Delete',
                                  hoverinfo='none')

        edges.append(FileDeleteEdges)

        marker = Marker(symbol='triangle-down', size=7,
                        color='rgb(171,171,171)')

        # Create the nodes...
        FileMoveNodes = Scatter(x=FileMoveX,
                                y=FileMoveY,
                                mode='markers',
                                marker=marker,
                                name='File Move',
                                text=filemovetxt,
                                hoverinfo='text')

        nodes.append(FileMoveNodes)

        # Create the edges for the nodes...
        FileMoveEdges = Scatter(x=FileMoveXe,
                                y=FileMoveYe,
                                mode='lines',
                                line=Line(shape='linear',
                                          color='rgb(171,171,171)'),
                                name='File Move',
                                hoverinfo='none')

        edges.append(FileMoveEdges)

        marker = Marker(symbol='triangle-up', size=7,
                        color='rgb(207,207,207)')

        # Create the nodes...
        FileReadNodes = Scatter(x=FileReadX,
                                y=FileReadY,
                                mode='markers',
                                marker=marker,
                                name='File Read',
                                text=filereadtxt,
                                hoverinfo='text')

        nodes.append(FileReadNodes)

        # Create the edges for the nodes...
        FileReadEdges = Scatter(x=FileReadXe,
                                y=FileReadYe,
                                mode='lines',
                                line=Line(shape='linear',
                                          color='rgb(207,207,207)'),
                                name='File Read',
                                hoverinfo='none')

        edges.append(FileReadEdges)

        # Create the edges for the nodes...
        LoadImageEdges = Scatter(x=LoadImageXe,
                                 y=LoadImageYe,
                                 mode='lines',
                                 line=Line(shape='linear',
                                           dash='dot'),
                                 name='Process Load Image',
                                 hoverinfo='none')

        edges.append(LoadImageEdges)

        # REGISTRY...

        marker = Marker(symbol='star', size=10)

        # Create the nodes...
        RegistryNodes = Scatter(x=RegistryX,
                                y=RegistryY,
                                mode='markers',
                                marker=marker,
                                name='Registry',
                                text=registrytxt,
                                hoverinfo='text')

        nodes.append(RegistryNodes)

        marker = Marker(symbol='triangle-down', size=7,
                        color='rgb(255,187,120)')

        # Create the nodes...
        RegistryWriteNodes = Scatter(x=RegistryWriteX,
                                     y=RegistryWriteY,
                                     mode='markers',
                                     marker=marker,
                                     name='Registry Write',
                                     text=registrywritetxt,
                                     hoverinfo='text')

        nodes.append(RegistryWriteNodes)

        # Create the edges for the nodes...
        RegistryWriteEdges = Scatter(x=RegistryWriteXe,
                                     y=RegistryWriteYe,
                                     mode='lines',
                                     line=Line(shape='linear',
                                               color='rgb(255,187,120)'),
                                     name='Registry Write',
                                     hoverinfo='none')

        edges.append(RegistryWriteEdges)

        marker = Marker(symbol='triangle-down', size=7,
                        color='rgb(255,128,14)')

        # Create the nodes...
        RegistryDeleteNodes = Scatter(x=RegistryDeleteX,
                                      y=RegistryDeleteY,
                                      mode='markers',
                                      marker=marker,
                                      name='Registry Delete',
                                      text=registrydeletetxt,
                                      hoverinfo='text')

        nodes.append(RegistryDeleteNodes)

        # Create the edges for the nodes...
        RegistryDeleteEdges = Scatter(x=RegistryDeleteXe,
                                      y=RegistryDeleteYe,
                                      mode='lines',
                                      line=Line(shape='linear',
                                                color='rgb(255,128,14)'),
                                      name='Registry Delete',
                                      hoverinfo='none')

        edges.append(RegistryDeleteEdges)

        marker = Marker(symbol='triangle-down', size=7,
                        color='rgb(123,102,210)')

        # Create the nodes...
        RegistryCreateNodes = Scatter(x=RegistryCreateX,
                                      y=RegistryCreateY,
                                      mode='markers',
                                      marker=marker,
                                      name='Registry Create',
                                      text=registrycreatetxt,
                                      hoverinfo='text')

        nodes.append(RegistryCreateNodes)

        # Create the edges for the nodes...
        RegistryCreateEdges = Scatter(x=RegistryCreateXe,
                                      y=RegistryCreateYe,
                                      mode='lines',
                                      line=Line(shape='linear',
                                                color='rgb(123,102,210)'),
                                      name='Registry Create',
                                      hoverinfo='none')

        edges.append(RegistryCreateEdges)

        marker = Marker(symbol='triangle-up', size=7,
                        color='rgb(207,207,207)')

        # Create the nodes...
        RegistryReadNodes = Scatter(x=RegistryReadX,
                                    y=RegistryReadY,
                                    mode='markers',
                                    marker=marker,
                                    name='Registry Read',
                                    text=registryreadtxt,
                                    hoverinfo='text')

        nodes.append(RegistryReadNodes)

        # Create the edges for the nodes...
        RegistryReadEdges = Scatter(x=RegistryReadXe,
                                    y=RegistryReadYe,
                                    mode='lines',
                                    line=Line(shape='linear',
                                              color='rgb(207,207,207)'),
                                    name='File Read',
                                    hoverinfo='none')

        edges.append(RegistryReadEdges)

        # Reverse the order and mush...
        output = []
        output += edges[::-1]
        output += nodes[::-1]

        # Return the plot data...
        return output

    def _generateannotations(self):
        """
        Internal function to generate annotations on the graph.

        :returns: A list of annotations for plotly.
        """
        annotations = Annotations()

        for node in self.digraph:
            if self.digraph.node[node]['type'] == 'PID':
                annotations.append(
                    Annotation(
                        text="{0}<br>PID: {1}".format(
                            self.nodemetadata[node]['name'],
                            self.nodemetadata[node]['pid']
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
            if self.digraph.node[node]['type'] == 'HOST':
                annotations.append(
                    Annotation(
                        text="HOST: {0}".format(
                            self.nodemetadata[node]['host']
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
            if self.digraph.node[node]['type'] == 'IP':
                annotations.append(
                    Annotation(
                        text="IP: {0}".format(
                            self.nodemetadata[node]['ip']
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

        return annotations

    def plotgraph(self,
                  graphvizprog='sfdp',
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
        :param filename: A file name for the interactive HTML plot.
        :param title: A title for the plot.
        :param auto_open: Set to false to not open the file in a web browser.
        :param image: An image type of 'png', 'jpeg', 'svg', 'webp', or None.
        :param image_filename: The file name for the exported image.
        :param image_height: The number of pixels for the image height.
        :param image_width: The number of pixels for the image width.
        :returns: Nothing

        """
        self.graphvizprog = graphvizprog

        # Layout the positions...
        self._create_positions_digraph()

        outputdata = self._generategraph()
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
