# tests.py

import unittest
from playfair import build_matrix, prepare_message, encryption, decrypt

class TestPlayfair(unittest.TestCase):

    def setUp(self):
        # Clé et matrice pour tous les tests
        self.key = "playfair"
        self.matrice = build_matrix(self.key)

    def test_prepare_message(self):
        # Test suppression des espaces et insertion de X
        msg = "balloon"
        prepared = prepare_message(msg)
        self.assertEqual(prepared, "balxloon")  # 'll' devient 'l x l'

        msg2 = "hi"
        prepared2 = prepare_message(msg2)
        self.assertEqual(prepared2, "hi")  # pas de modification si pas de doublon

    def test_encryption_decryption(self):
        messages = [
            "hello",
            "balloon",
            "testmessage",
            "playfaircipher",
            "i j merge",
        ]
        for msg in messages:
            cipher = encryption(msg, self.matrice)
            decrypted = decrypt(cipher, self.matrice)
            # On enlève les espaces et convertit en minuscules pour comparaison
            clean_msg = "".join([c.lower() for c in msg if c.isalpha()]).replace("j", "i")
            self.assertEqual(decrypted, prepare_message(clean_msg))

    def test_matrix_building(self):
        matrix = build_matrix("keyword")
        # Vérifie que toutes les lettres (sans J) sont présentes
        all_letters = [c for row in matrix for c in row]
        self.assertEqual(len(all_letters), 25)
        self.assertNotIn("j", all_letters)

if __name__ == "__main__":
    unittest.main()