"""
TP 1 - CHIFFREMENT CLASSIQUE
Exercices intégrés: César, Vigenère, Hill, OTP
Démonstration complète des vulnérabilités
"""

from crypto_paths import setup_tp1_paths

setup_tp1_paths()

# Import Caesar cipher modules
from caesar import caesar_cipher, caesar_decipher
from caesar_attacks import (
    brute_force_caesar,
    frequency_analysis_caesar,
    chi_squared_attack_caesar,
    calculate_index_of_coincidence
)

# Import Vigenère cipher modules
from vignere import encrypt_vignere, decrypt_vignere
from vignere_attacks import (
    kasiski_test,
    estimate_key_length_kasiski,
    index_of_coincidence_attack,
    recover_key_from_ic
)

# Import Hill cipher modules
from hill import encrypt_hill, decrypt_hill
from hill_attacks import known_plaintext_attack_hill, verify_key

# Import OTP modules
from otp import encryption, decryption
from otp_attacks import otp_key_reuse_attack, crib_dragging_attack

from tp_console import (
    banner,
    demo,
    end_footer,
    error_exercise,
    info,
    label,
    print_block,
    result,
    section,
    subsection,
    summary,
)


def exercise_1_1_caesar():
    """Exercice 1.1 - Chiffre de César"""
    section("1.1 — CHIFFRE DE CÉSAR")
    
    plaintext = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
    shift = 7
    ciphertext = caesar_cipher(plaintext, shift)
    
    label("Clair", plaintext)
    label("Clé (shift)", shift)
    label("Chiffré", ciphertext)
    
    decrypted = caesar_decipher(ciphertext, shift)
    label("Déchiffré", decrypted)
    result("Vérification", decrypted == plaintext)
    
    subsection("Attaque 1 — Force Brute (avec dictionnaire)")
    info(f"L'attaquant n'a que le chiffré : {ciphertext}")
    
    candidates = brute_force_caesar(ciphertext, top_n=3)
    for i, (try_shift, try_plain, score) in enumerate(candidates, 1):
        print(f"{i}. Shift {try_shift:2d}: {try_plain[:50]:50s} | Confiance: {score:.1%}")
    
    subsection("Attaque 2 — Analyse de Fréquences (Indice de Coïncidence)")
    
    ic_plain = calculate_index_of_coincidence(plaintext)
    ic_cipher = calculate_index_of_coincidence(ciphertext)
    
    label("IC du clair", f"{ic_plain:.4f}")
    label("IC du chiffré", f"{ic_cipher:.4f}")
    label("IC français", "0.0740 (référence)")
    
    shift_recovered, plain_recovered, ic_recovered = frequency_analysis_caesar(ciphertext)
    
    info("Résultat attaque IC :")
    label("Shift détecté", shift_recovered)
    label("IC obtenu", f"{ic_recovered:.4f}")
    label("Clair trouvé", plain_recovered[:50])
    
    subsection("Attaque 3 — Analyse Chi-squared")
    
    candidates_chi = chi_squared_attack_caesar(ciphertext, top_n=3)
    info("Top 3 candidats (chi-squared) :")
    for i, (try_shift, try_plain, chi_sq) in enumerate(candidates_chi, 1):
        print(f"{i}. Shift {try_shift:2d}: χ² = {chi_sq:8.2f} | {try_plain[:50]}")


def exercise_1_2_vigenere():
    """Exercice 1.2 - Chiffre de Vigenère"""
    section("1.2 — CHIFFRE DE VIGENÈRE")
    
    plaintext = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG" * 2
    key = "SECRET"
    ciphertext = encrypt_vignere(plaintext, key)
    
    label("Clair", f"{plaintext[:60]}...")
    label("Clé", key)
    label("Chiffré", f"{ciphertext[:60]}...")
    
    decrypted = decrypt_vignere(ciphertext, key)
    result("Déchiffrement", decrypted == plaintext)
    
    subsection("Attaque 1 — Test de Kasiski (Trigrammes Répétés)")
    
    info("Recherche de trigrammes répétés…")
    kasiski_results = kasiski_test(ciphertext)
    
    print(f"Trigrammes/patterns répétés trouvés: {len(kasiski_results)}")
    for i, (pattern, positions, distances, divisors) in enumerate(kasiski_results[:5], 1):
        print(f"  {i}. '{pattern}' aux positions {positions[:3]} "
              f"(distances: {distances})")
    
    # Estimation longueur clé
    key_length_estimates = estimate_key_length_kasiski(ciphertext, top_n=5)
    print(f"\nEstimation longueur clé par Kasiski:")
    for key_len, votes in key_length_estimates[:5]:
        print(f"  Longueur {key_len}: {votes} votes")
    
    subsection("Attaque 2 — Analyse par Indice de Coïncidence")
    
    ic_scores, (best_length, best_ic) = index_of_coincidence_attack(ciphertext)
    
    print(f"\nRésultats IC pour chaque longueur de clé:")
    print(f"{'Longueur':<10} {'IC Value':<12} {'Δ from French':<15}")
    print("-" * 37)
    for length in sorted(ic_scores.keys())[:8]:
        ic = ic_scores[length]
        delta = abs(ic - 0.074)
        print(f"{length:<10} {ic:<12.4f} {delta:<15.4f}")
    
    print(f"\nLongueur de clé estimée: {best_length} (IC={best_ic:.4f})")
    
    subsection("Attaque 3 — Récupération de la Clé")
    
    recovered_key = recover_key_from_ic(ciphertext, best_length)
    
    label("Clé originale", key)
    label("Clé récupérée", recovered_key)
    
    if len(recovered_key) == len(key):
        matches = sum(1 for a, b in zip(recovered_key, key) if a == b)
        print(f"Correspondances: {matches}/{len(key)}")
    
    # Essai de déchiffrement
    decrypted_recovered = decrypt_vignere(ciphertext, recovered_key)
    print(f"\nDéchiffrement avec clé récupérée:")
    print(f"  {decrypted_recovered[:60]}...")
    print(f"  Correct: {'✓ OUI' if decrypted_recovered == plaintext else '✗ (proche mais pas exact)'}")


def exercise_1_3_hill():
    """Exercice 1.3 - Chiffre de Hill"""
    section("1.3 — CHIFFRE DE HILL")
    
    demo("Hill 2×2")
    
    plaintext_2x2 = "HILLCIPHER"
    key_2x2 = [[5, 8], [17, 3]]
    
    ciphertext_2x2 = encrypt_hill(plaintext_2x2, key_2x2)
    
    print(f"\nMatrice clé (2×2):")
    for row in key_2x2:
        print(f"  {row}")
    
    print(f"\nClair:   {plaintext_2x2}")
    print(f"Chiffré: {ciphertext_2x2}")
    
    # Déchiffrement
    decrypted_2x2 = decrypt_hill(ciphertext_2x2, key_2x2)
    print(f"Déchiffré: {decrypted_2x2.rstrip('X')}")
    print(f"Correct: {'✓ OUI' if decrypted_2x2.rstrip('X') == plaintext_2x2 else '✗ NON'}")
    
    # Attaque: Connaissant clair et chiffré
    subsection("Attaque à Clair Connu (2×2)")
    
    print(f"\nL'attaquant sait:")
    print(f"  Clair:   {plaintext_2x2}")
    print(f"  Chiffré: {ciphertext_2x2}")
    print(f"  Taille bloc: 2 (matrice 2×2)")
    
    try:
        recovered_key = known_plaintext_attack_hill(plaintext_2x2, ciphertext_2x2, block_size=2)
        print(f"\nMatrice clé récupérée:")
        for i in range(2):
            print(f"  {list(recovered_key.row(i))}")
        
        # Vérification
        is_correct = verify_key(plaintext_2x2, ciphertext_2x2, recovered_key, 2)
        print(f"\nVérification: {'✓ CORRECTE' if is_correct else '✗ ÉCHOUÉE'}")
        
        # Déchiffrement avec clé récupérée
        key_as_list = [list(recovered_key.row(i)) for i in range(2)]
        decrypted_with_recovered = decrypt_hill(ciphertext_2x2, key_as_list)
        print(f"Déchiffrement: {decrypted_with_recovered.rstrip('X')}")
        
    except Exception as e:
        print(f"Erreur: {e}")
    
    # Hill 3x3
    demo("Hill 3×3")
    
    plaintext_3x3 = "SECRETMESSAGE"
    key_3x3 = [[1, 2, 3], [0, 5, 2], [2, 0, 3]]
    
    ciphertext_3x3 = encrypt_hill(plaintext_3x3, key_3x3)
    
    print(f"\nMatrice clé (3×3):")
    for row in key_3x3:
        print(f"  {row}")
    
    print(f"\nClair:   {plaintext_3x3}")
    print(f"Chiffré: {ciphertext_3x3}")
    
    # Attaque 3x3
    subsection("Attaque à Clair Connu (3×3)")
    
    try:
        recovered_key_3x3 = known_plaintext_attack_hill(plaintext_3x3, ciphertext_3x3, block_size=3)
        print(f"\nMatrice clé récupérée:")
        for i in range(3):
            print(f"  {list(recovered_key_3x3.row(i))}")
        
        is_correct_3x3 = verify_key(plaintext_3x3, ciphertext_3x3, recovered_key_3x3, 3)
        print(f"\nVérification: {'✓ CORRECTE' if is_correct_3x3 else '✗ ÉCHOUÉE'}")
        
    except Exception as e:
        print(f"Erreur: {e}")


def exercise_1_4_otp():
    """Exercice 1.4 - One-Time Pad (Vernam)"""
    section("1.4 — ONE-TIME PAD (VERNAM)")
    
    demo("OTP Basique")
    
    message = "THEQUICKBROWNFOX"
    ciphertext, key = encryption(message)
    decrypted = decryption(ciphertext, key)
    
    print(f"\nMessage:       {message}")
    print(f"Clé (hex):     {key.hex()[:40]}...")
    print(f"Chiffré (hex): {ciphertext.hex()}")
    print(f"Déchiffré:     {decrypted}")
    print(f"Correct: {'✓ OUI' if decrypted == message else '✗ NON'}")
    
    # Vulnérabilité: Réutilisation de clé
    subsection("Vulnérabilité — Réutilisation de Clé")
    
    m1 = "HELLO"
    m2 = "WORLD"
    
    result = otp_key_reuse_attack(m1, m2)
    
    print(f"\nScénario d'attaque:")
    print(f"  Message 1:  {result['message1']}")
    print(f"  Message 2:  {result['message2']}")
    print(f"  Clé (même pour les deux!): {result['key'].hex()}")
    
    print(f"\nRésultat:")
    print(f"  C1:        {result['ciphertext1'].hex()}")
    print(f"  C2:        {result['ciphertext2'].hex()}")
    print(f"  C1 ⊕ C2:   {result['ciphertext1_xor_ciphertext2'].hex()}")
    print(f"  M1 ⊕ M2:   {result['message1_xor_message2'].hex()}")
    print(f"  Match:     {'✓ OUI (VULNÉRABLE!)' if result['ciphertext1_xor_ciphertext2'] == result['message1_xor_message2'] else '✗ NON'}")
    
    # Crib dragging
    subsection("Attaque — Crib Dragging")
    
    m1_long = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
    m2_long = "THEATTACKERHASTHESECRETKEY"
    
    c1, key_shared = encryption(m1_long)
    c2, _ = encryption(m2_long)  # Réutilisation de clé (vulnérabilité!)
    
    print(f"\nL'attaquant sait:")
    print(f"  C1 (hex): {c1.hex()[:40]}...")
    print(f"  C2 (hex): {c2.hex()[:40]}...")
    print(f"  Suppose que M1 contient 'THE'")
    
    crib_results = crib_dragging_attack(c1, c2, "THE")
    
    print(f"\nPositions où 'THE' pourrait être dans M1:")
    for result in crib_results[:3]:
        print(f"  Position {result['position']:2d}: "
              f"M2 aurait '{result['implied_message2_segment']}'")
    
    print(f"\nConclusion: Même TEXT COURT révèle de l'information!")


def main():
    """Exécuter tous les exercices du TP 1"""
    banner(1, "CHIFFREMENT CLASSIQUE", "César, Vigenère, Hill, OTP (Vernam)")
    
    try:
        exercise_1_1_caesar()
    except Exception as e:
        error_exercise("1.1", e)
    
    try:
        exercise_1_2_vigenere()
    except Exception as e:
        error_exercise("1.2", e)
    
    try:
        exercise_1_3_hill()
    except Exception as e:
        error_exercise("1.3", e)
    
    try:
        exercise_1_4_otp()
    except Exception as e:
        error_exercise("1.4", e)
    
    summary("RÉSUMÉ DES VULNÉRABILITÉS")
    print_block("""
    CÉSAR:
      ✗ Espace de clé très petit (26 possibilités)
      ✗ Vulnérable à la force brute
      ✗ Vulnérable à l'analyse de fréquences
      → Indice de Coïncidence trahit le clair français

    VIGENÈRE:
      ✗ Si clé est courte, elle se répète
      ✗ Trigrammes répétés révèlent la longueur de clé (Kasiski)
      ✗ IC pour chaque décalage révèle chaque lettre de clé
      → Récupération complète de la clé possible

    HILL:
      ✗ Structure linéaire: C = K × P (mod 26)
      ✗ Attaque à clair connu: K = C × P⁻¹ (mod 26)
      ✗ Peu de blocs suffisent pour retrouver K
      → Totalement cassé avec clair connu

    OTP:
      ✗ Réutilisation de clé: C1 ⊕ C2 = M1 ⊕ M2
      ✗ Crib dragging révèle partiellement les messages
      ✗ Supposé "parfait" mais pratiquement impossible:
        - Distribution sécurisée de clés longues
        - Génération de nombres aléatoires vraiment random
      → Théoriquement sûr, pratiquement inutilisable

    CONCLUSION:
      Les chiffrements classiques sont tous cassables moderément.
      Passage aux chiffreurs modernes (AES, ChaCha20) est nécessaire.
    """)
    
    end_footer(1)


if __name__ == "__main__":
    main()
