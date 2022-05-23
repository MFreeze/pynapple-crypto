import unidecode

class MonoAlphabeticSubstitution(object):

    """A small class to perform mono-alphabetic substitution cyphering"""

    def __init__(self, encrypted_alphabet):
        """TODO: to be defined.

        :encrypted_alphabet: TODO

        """
        normalized_alphabet = unidecode.unidecode(encrypted_alphabet).lower()
        source_alphabet = "abcdefghijklmnopqrstuvwxyz"
        self.cypher_key = {}
        self.decypher_key = {}

        for i in range(len(source_alphabet)):
            try:
                self.cypher_key[source_alphabet[i]] = normalized_alphabet[i]
            except IndexError:
                self.cypher_key[source_alphabet[i]] = source_alphabet[i]

        for key,val in self.cypher_key.items():
            self.decypher_key[val] = key

    def cypher(self, string):
        norm_str = unidecode.unidecode(string).lower()
        return "".join(self.cypher_key.get(c,c) for c in norm_str)

    def decypher(self, string):
        norm_str = unidecode.unidecode(string).lower()
        return "".join(self.decypher_key.get(c,c) for c in norm_str)

# test = MonoAlphabeticSubstitution("qwertyuiopASDFGHJKLzxcvbnm")
# c = test.cypher("Une petit chaîne chiffrée avec pas mal d'accents et autres merdes! xD")
# print(c)
# print(test.decypher(c))
