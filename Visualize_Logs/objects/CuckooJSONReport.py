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
                 plotnetwork=True,
                 plotfiles=True,
                 plotregistry=True):
        """
        The JSON report file is read and parsed using this class.  This
        could take a whiel depending on how big your JSON report is.

        This has been tested with the cuckoo-modifed version, but it may
        work with Cuckoo (proper) as well.

        :param jsonreportfile: The path to the JSON report file.
        :type jsonreportfile: A string.
        :param plotnetwork: Set to False to ignore network activity.
        :param plotfiles: Set to False to ignore file activity.
        :param plotregistry: Set to False to ignore registry activity.
        :returns: An object.
        :rtype: CuckooJSONReport object.
        """
        if not os.path.exists(jsonreportfile):
            raise Exceptions.VisualizeLogsInvalidFile(jsonreportfile)
        else:
            self.jsonreportfile = jsonreportfile

        with open(self.jsonreportfile, 'r') as jsonfile:
            self.jsonreportdata = json.load(jsonfile)

        # Create a network graph...
        self.digraph = networkx.DiGraph()

        # Add all the processes to the graph...
        self._add_all_processes()

        if plotnetwork is True:
            # Add network activity to the graph...
            self._add_network_activity()

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
        self.nodemetadata[nodename]['environ'] = processtreedict['environ']
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

            calls = self.nodemetadata[nodename]['calls']
            calls['timestamp'] = pandas.to_datetime(calls['timestamp'])

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

    def _add_network_activity(self):
        """
        Internal function that adds network data to the graph.
        Assumes processes have already been plotted.

        :returns:  Nothin.
        """
        self.domains =\
            pandas.DataFrame(self.jsonreportdata['network']['domains'])
        metadata = self.nodemetadata.copy()
        for node in metadata:
            if metadata[node]['node_type'] == 'PID':
                if 'calls' in metadata[node]:
                    calls = metadata[node]['calls']

                    # Get DNS lookups...
                    self._add_dns_lookups(node, calls)
                    # Add socket activity...
                    self._add_sockets(node, calls)

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

                ips = self.domains[self.domains['domain'] == hostname]

                for j, ip in ips.iterrows():
                    ipnodename = self._add_ip(ip['ip'])
                    self.digraph.add_edge(hostnodename, ipnodename)

    def _add_host(self, host):
        """
        Internal function to add a host if it does not exist.

        :param host: Host name.
        :returns: Node name for the host.
        """
        hostnodename = "HOST {0}".format(host)
        if hostnodename not in self.nodemetadata:
            self.nodemetadata[hostnodename] = dict()
            self.nodemetadata[hostnodename]['node_type'] = 'IP'
            self.nodemetadata[hostnodename]['host'] = host
            self.digraph.add_node(hostnodename, type='HOST')

        return hostnodename

    def _add_ip(self, ip):
        """
        Internal function to add a host if it does not exist.

        :param ip: IP address.
        :returns: Node name for the IP address.
        """
        ipnodename = "IP {0}".format(ip)
        if ipnodename not in self.nodemetadata:
            self.nodemetadata[ipnodename] = dict()
            self.nodemetadata[ipnodename]['node_type'] = 'IP'
            self.nodemetadata[ipnodename]['ip'] = ip
            self.digraph.add_node(ipnodename, type='IP')

        return ipnodename

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

        # Hover Text...
        proctxt = []
        hosttxt = []
        iptxt = []
        sockettxt = []
        tcpconnecttxt = []

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
                    "Parent PID: {3}"
                    .format(
                        self.nodemetadata[node]['pid'],
                        self.nodemetadata[node]['module_path'],
                        cmdline,
                        self.nodemetadata[node]['parent_id']
                        )
                               )
            if self.digraph.node[node]['type'] == 'HOST':
                HostX.append(self.pos[node][0])
                HostY.append(self.pos[node][1])
                hosttxt.append(
                    "HOST: {0}"
                    .format(
                        self.nodemetadata[node]['host'],
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

        # Create the edges for the nodes...
        GetNameEdges = Scatter(x=GetNameXe,
                               y=GetNameYe,
                               mode='lines',
                               line=Line(shape='linear'),
                               name='DNS Query',
                               hoverinfo='none')

        nodes.append(HostNodes)
        edges.append(GetNameEdges)

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

        # Create the edges for the nodes...
        DNSEdges = Scatter(x=DNSXe,
                           y=DNSYe,
                           mode='lines',
                           line=Line(shape='linear'),
                           name='DNS Response',
                           hoverinfo='none')

        nodes.append(IPNodes)
        edges.append(DNSEdges)

        # SOCKETS...

        marker = Marker(symbol='diamond', size=7)

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
                              line=Line(shape='linear'),
                              name='Create Socket',
                              hoverinfo='none')

        nodes.append(SocketNodes)
        edges.append(SocketEdges)

        # TCP CONNECTS...

        marker = Marker(symbol='triangle-down', size=7)

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
                                  line=Line(shape='linear'),
                                  name='TCP Connect',
                                  hoverinfo='none')

        nodes.append(TCPConnectNodes)
        edges.append(TCPConnectEdges)

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
