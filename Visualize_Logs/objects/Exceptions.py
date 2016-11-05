#
# Exceptions
#


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
