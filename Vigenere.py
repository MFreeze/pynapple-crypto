import unidecode

class Vigenere(object):

    """Simple Vigenere cyphering and decyphering"""

    def __init__(self, key):
        """TODO: to be defined.

        :key: TODO
        """
        self._keystream = [ ord(c) - 96 for c in unidecode.unidecode(key).lower()]
        self._keylen = len(self._keystream)
        
    def cypher(self, message):
        norm_str = unidecode.unidecode(message).lower()
        cur_index = 0
        result = ""
        for i in [ ord(c) - 97 for c in norm_str ]:
            if 0 <= i < 26:
                result += chr(((i + self._keystream[cur_index]) % 26) + 97)
                cur_index = (cur_index + 1) % self._keylen
            else:
                result += chr(i + 97)
        return result

    def decypher(self, message):
        norm_str = unidecode.unidecode(message).lower()
        cur_index = 0
        result = ""
        for i in [ ord(c) - 97 for c in norm_str ]:
            if 0 <= i < 26:
                result += chr(((i - self._keystream[cur_index]) % 26) + 97)
                cur_index = (cur_index + 1) % self._keylen
            else:
                result += chr(i + 97)
        return result

