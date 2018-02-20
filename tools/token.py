from tools.message import Message
from collections import OrderedDict

class InvalidToken(Exception):
    """ Exception raised when an invalid string is passed 
    as a user token.
    """
    def __init__(self):
        Exception.__init__(self, "Unable to parse message as token.")

class Token():
    def __init__(self, data, sep_field, sep_key):
        clean_items = list(data.items())
        for (key, value) in clean_items:
            key.eatChars([sep_field, sep_key])
            value.eatChars([sep_field, sep_key])
        self.data = OrderedDict(clean_items)
        self.sep_field = sep_field
        self.sep_key = sep_key
        self.msg = sep_field.join(sep_key.join(item) for item in self.data.items())

    @classmethod
    def fromMsg(cls, msg, sep_field, sep_key):
        fields = [sub.split(sep_key) for sub in msg.split(sep_field)]
        cls.data = OrderedDict([(field[0], field[1]) for field in fields])
        cls.sep_field = sep_field
        cls.sep_key = sep_key
        cls.msg = msg
        return cls
