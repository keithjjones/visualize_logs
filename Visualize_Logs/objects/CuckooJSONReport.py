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

    def __init__(self, jsonreportfile=None):
        """
        The JSON report file is read and parsed using this class.  This
        could take a whiel depending on how big your JSON report is.

        This has been tested with the cuckoo-modifed version, but it may
        work with Cuckoo (proper) as well.

        :param jsonreportfile: The path to the JSON report file.
        :type jsonreportfile: A string.
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

    def _add_all_processes(self):
        """
        Internal function to add processess from JSON report
        process tree.

        :returns: Nothing.
        """
        self.processtree = self.jsonreportdata['behavior']['processtree']

        self.rootpid = self.processtree[0]['pid']

        for process in self.processtree:
            self._add_processes_recursive(process)

    def _add_processes_recursive(self, processtreedict):
        """
        Internal function to add processes recursively from
        a dict representing the JSON process tree.

        :param processtreedict:  A dict of data from the process tree.
        :returns: Nothin.
        """
        self.digraph.add_node("PID {0}".format(processtreedict['pid']),
                              type='PID',
                              parent_id="{0}"
                              .format(processtreedict['parent_id']))

        for child in processtreedict['children']:
            self._add_processes_recursive(child)

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
                    self.digraph, prog=self.graphvizprog)
