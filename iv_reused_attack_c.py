# author: linzheng tan 
# this is a demo showing the iv reused attack with SAME AAD, different message length
# and only one message block (<= 128 bits)

from gcm import aes_gcm_encrypt, aes_gcm_decrypt
from ghash import gcm_gf_mult
from gcm_auxiliary import (
    hex_to_list, list_to_hex, xor_bytes, 
    int_to_list, string_to_list
)
from attack_auxiliary import solve_quadratic_gf2_128

def pad_block(data):
    """Pad data to 16 bytes (128 bits) with zeros."""
    return data + [0] * (16 - len(data))

def iv_reused_attack_c():
    # Simulation of the shared key between the Bank and Alice
    key = hex_to_list("feffe9928665731c6d6a8f9467308308")
    # FATAL ERROR: The same IV is reused for different messages
    reused_iv = hex_to_list("cafebabefacedbaddecaf888")
    
    # Common Financial Protocol Header (Same AAD)
    aad_str = "BankProtocol:v1"
    aad = string_to_list(aad_str)
    
    print("--- STEP 1: Intercepting Traffic (3 Messages for Disambiguation) ---")
    
    # Message 1 (Short): "Pay David $100" (14 bytes)
    p1_str = "Pay David $100"  
    p1 = string_to_list(p1_str)
    c1, t1 = aes_gcm_encrypt(p1, key, reused_iv, aad)
    
    # Message 2 (Longer): "Pay Bob   $2000 " (16 bytes)
    p2_str = "Pay Bob   $2000 " 
    p2 = string_to_list(p2_str)
    c2, t2 = aes_gcm_encrypt(p2, key, reused_iv, aad)
    
    # Message 3 (Any length): Used to check which root is correct
    p3_str = "Balance Query" 
    p3 = string_to_list(p3_str)
    c3, t3 = aes_gcm_encrypt(p3, key, reused_iv, aad)

    print(f"[*] AAD: '{aad_str}'")
    
    # Formatting for aligned output
    # Using padding to ensure the '|' aligns perfectly
    msg1_info = f"[*] Msg 1: '{p1_str}' (Len: {len(p1)*8} bits)"
    msg2_info = f"[*] Msg 2: '{p2_str}' (Len: {len(p2)*8} bits)"
    msg3_info = f"[*] Msg 3: '{p3_str}' (Len: {len(p3)*8} bits)"
    
    # Pad to 45 characters (adjustable based on longest message)
    print(f"{msg1_info:<45} | Tag: {list_to_hex(t1)}")
    print(f"{msg2_info:<45} | Tag: {list_to_hex(t2)}")
    print(f"{msg3_info:<45} | Tag: {list_to_hex(t3)} (Verifier)")
    
    print("\n--- STEP 2: Mathematical Derivation (Quadratic Equation) ---")
    # Equation: (Delta_C) * H^2 + (Delta_L) * H + (Delta_T) = 0
    
    delta_t = xor_bytes(t1, t2)
    
    # CRITICAL: Coefficients must be calculated on PADDED blocks!
    c1_padded = pad_block(c1)
    c2_padded = pad_block(c2)
    delta_c = xor_bytes(c1_padded, c2_padded)
    
    # Construct Length Blocks
    aad_len_bits = len(aad) * 8
    l1_block = int_to_list(aad_len_bits, 8) + int_to_list(len(p1)*8, 8)
    l2_block = int_to_list(aad_len_bits, 8) + int_to_list(len(p2)*8, 8)
    delta_l = xor_bytes(l1_block, l2_block)
    
    print(f"[!] Quadratic Equation: A*x^2 + B*x + C = 0")
    print(f"    Coeff A (Delta C): {list_to_hex(delta_c)}")
    print(f"    Coeff B (Delta L): {list_to_hex(delta_l)}")
    print(f"    Coeff C (Delta T): {list_to_hex(delta_t)}")
    
    print("[*] Solving equation using Gaussian Elimination over GF(2)...")
    
    roots = solve_quadratic_gf2_128(delta_c, delta_l, delta_t)
    
    if not roots:
        print("[FAIL] Solver could not find any solution.")
        return

    print(f"[*] Found {len(roots)} candidate roots for H.")

    print("\n--- STEP 3: Disambiguation (Finding the Real H) ---")
    real_h = None
    recovered_e_j0 = None
    
    # Pre-calculate padded blocks for verification loop to avoid repetition errors
    aad_padded = pad_block(aad)
    l3_block = int_to_list(aad_len_bits, 8) + int_to_list(len(p3)*8, 8)
    c3_padded = pad_block(c3)

    for i, h_cand in enumerate(roots):
        # 1. Recover Ek(J0) using Msg 1 and this candidate H
        h_sq = gcm_gf_mult(h_cand, h_cand)
        h_cu = gcm_gf_mult(h_sq, h_cand)
        
        term_aad = gcm_gf_mult(aad_padded, h_cu)
        term_c1  = gcm_gf_mult(c1_padded, h_sq)
        term_l1  = gcm_gf_mult(l1_block, h_cand)
        
        sum_terms = xor_bytes(xor_bytes(term_aad, term_c1), term_l1)
        e_j0_cand = xor_bytes(t1, sum_terms)
        
        # 2. Check validity using Msg 3
        check_aad = gcm_gf_mult(aad_padded, h_cu)
        check_c3  = gcm_gf_mult(c3_padded, h_sq)
        check_l3  = gcm_gf_mult(l3_block, h_cand)
        
        ghash3 = xor_bytes(xor_bytes(check_aad, check_c3), check_l3)
        t3_calculated = xor_bytes(ghash3, e_j0_cand)
        
        if list_to_hex(t3_calculated) == list_to_hex(t3):
            print(f"    [MATCH] Candidate #{i+1} validates against Msg 3!")
            print(f"    -> H:      {list_to_hex(h_cand)}")
            print(f"    -> Ek(J0): {list_to_hex(e_j0_cand)}")
            real_h = h_cand
            recovered_e_j0 = e_j0_cand
            break
        else:
            print(f"    [FAIL] Candidate #{i+1} mismatch on Msg 3.")

    if real_h is None or recovered_e_j0 is None:
        print("[FAIL] Neither root validated. Something is wrong.")
        return

    print("\n--- STEP 4: Forgery ---")

    p_forged = "Pay Eve $9999999" 
    p_forged_bytes = string_to_list(p_forged)
    print(f"[*] Target Forged Message: '{p_forged}'")
    
    # 1. Encrypt using Keystream from Message 2
    # Known plaintext/ciphertext pair (e.g., attacker-injected "AAAA..." message)
    known_p_str = "AAAAAAAAAAAAAAAA"
    known_c, _ = aes_gcm_encrypt(string_to_list(known_p_str), key, reused_iv)

    keystream = xor_bytes(known_c, string_to_list(known_p_str))
    
    if len(p_forged_bytes) > len(keystream):
        print("[!] Error: Forged message too long for captured keystream.")
        return

    c_forged = xor_bytes(p_forged_bytes, keystream[:len(p_forged_bytes)])
    
    # 2. Generate Tag
    c_forged_padded = pad_block(c_forged)
    l_forged_block = int_to_list(aad_len_bits, 8) + int_to_list(len(c_forged)*8, 8)
    
    h_sq = gcm_gf_mult(real_h, real_h)
    h_cu = gcm_gf_mult(h_sq, real_h)
    
    ghash_aad = gcm_gf_mult(aad_padded, h_cu)
    ghash_c   = gcm_gf_mult(c_forged_padded, h_sq)
    ghash_l   = gcm_gf_mult(l_forged_block, real_h)
    
    t_forged = xor_bytes(xor_bytes(xor_bytes(ghash_aad, ghash_c), ghash_l), recovered_e_j0)
    
    print(f"[*] Forged Ciphertext: {list_to_hex(c_forged)}")
    print(f"[*] Forged Tag:        {list_to_hex(t_forged)}")

    print("\n--- STEP 5: Bank Verification ---")
    received_p, is_valid = aes_gcm_decrypt(
        c_forged, 
        key, 
        reused_iv, 
        aad=aad, 
        mac=t_forged
    )

    if is_valid:
        print("[SUCCESS] Bank System: MAC verification PASSED!")
        print(f"[SUCCESS] Bank executing instruction: '{received_p}'")
    else:
        print("[FAIL] Bank System: ERROR! Tampering detected.")

if __name__ == "__main__":
    iv_reused_attack_c()
