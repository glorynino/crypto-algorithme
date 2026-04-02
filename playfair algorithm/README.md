# Playfair Cipher Implementation in Python

## 📌 Description

This project implements the **Playfair cipher**, a classical digraph substitution cipher invented by **Charles Wheatstone** in 1854.  
It encrypts plaintext in **digraphs (pairs of letters)** using a **5x5 key matrix**, providing stronger security than a simple monoalphabetic cipher.

This Python implementation handles:

- Key matrix generation (5x5) with duplicate removal  
- Merging `I` and `J` into a single cell  
- Preprocessing of plaintext:
  - Conversion to lowercase  
  - Removal of non-alphabetic characters  
  - Handling repeated letters in digraphs by inserting `X`  
  - Appending `X` if the message has an odd length  
- Encryption and decryption according to Playfair rules

---

## 🔑 How It Works

1. **Key Matrix Construction**  
   - User provides a keyword.  
   - Duplicate letters are removed.  
   - Remaining letters of the alphabet (without `J`) are appended.  
   - A 5x5 matrix is created.

2. **Message Preparation**  
   - Convert message to lowercase.  
   - Replace `J` with `I`.  
   - Remove spaces and non-alphabetic characters.  
   - Insert `X` between repeated letters in a digraph.  
   - Append `X` if message length is odd.

3. **Encryption Rules**
   - **Same row**: replace each letter with the letter to its **right** (wrap around to the left if needed).  
   - **Same column**: replace each letter with the letter **below** (wrap around to top if needed).  
   - **Rectangle**: swap the columns of the two letters.

4. **Decryption Rules**
   - Same as encryption, but:
     - **Row → move left**  
     - **Column → move up**  
     - Rectangle rule is identical  

