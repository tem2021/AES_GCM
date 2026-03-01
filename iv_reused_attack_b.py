# author: linzheng tan 
# this is a demo showing the iv reused attack without AAD, same message length
# and only one message block (<= 128 bits)

from gcm import aes_gcm_encrypt, aes_gcm_decrypt
from ghash import gcm_gf_mult
from gcm_auxiliary import (
    hex_to_list, list_to_hex, xor_bytes, 
    int_to_list, string_to_list
)
from aes import aes128
from attack_auxiliary import gf_inverse, gf_sqrt

def iv_reused_attack_b():
    # Simulation of the shared key between the Bank and Alice
    key = hex_to_list("feffe9928665731c6d6a8f9467308308")
    # FATAL ERROR: The same IV is reused for different messages
    reused_iv = hex_to_list("cafebabefacedbaddecaf888")
    
    print("--- STEP 1: Attacker intercepts two messages with the same IV ---")
    p1_str = "Pay David $1000 " 
    c1, t1 = aes_gcm_encrypt(string_to_list(p1_str), key, reused_iv)
    
    p2_str = "Pay Bob   $2000 "
    c2, t2 = aes_gcm_encrypt(string_to_list(p2_str), key, reused_iv)

    print(f"[*] Intercepted Msg 1: '{p1_str}' | Tag: {list_to_hex(t1)}")
    print(f"[*] Intercepted Msg 2: '{p2_str}' | Tag: {list_to_hex(t2)}")

    print("\n--- STEP 2: Mathematical Recovery (Cracking H and E(J0)) ---")
    print("[!] Solving equation: T1 ^ T2 = (C1 ^ C2) * H^2")
    
    delta_t = xor_bytes(t1, t2)
    delta_c = xor_bytes(c1, c2)
    
    # A. Solve for H^2 = Delta_T * inv(Delta_C)
    print("[*] Calculating Multiplicative Inverse of Delta_C...")
    inv_delta_c = gf_inverse(delta_c)
    h_squared = gcm_gf_mult(delta_t, inv_delta_c)
    
    # B. Solve for H = sqrt(H^2)
    print("[*] Extracting Square Root in GF(2^128)...")
    h = gf_sqrt(h_squared)
    
    # Verification
    actual_h = aes128([0] * 16, key)
    print(f"[!] Recovered H: {list_to_hex(h)}")
    print(f"    (Actual H:   {list_to_hex(actual_h)})")

    # C. Recover masking value E(J0) = T1 ^ C1*H^2 ^ L*H
    l_block = int_to_list(0, 8) + int_to_list(128, 8) 
    ch2 = gcm_gf_mult(c1, h_squared)
    lh = gcm_gf_mult(l_block, h)
    recovered_e_j0 = xor_bytes(xor_bytes(t1, ch2), lh)
    
    print(f"[!] Recovered Ek(J0): {list_to_hex(recovered_e_j0)}")

    print("\n--- STEP 3: Malicious Tampering & Forgery ---")
    p_forged = "Pay Eve $9999999" 
    print(f"[*] Target Forged Message: '{p_forged}'")
    
    keystream = xor_bytes(c1, string_to_list(p1_str))
    c_forged = xor_bytes(string_to_list(p_forged), keystream)
    
    ch2_forged = gcm_gf_mult(c_forged, h_squared)
    t_forged = xor_bytes(xor_bytes(ch2_forged, lh), recovered_e_j0)
    
    print(f"[*] Forged Ciphertext: {list_to_hex(c_forged)}")
    print(f"[*] Forged Tag:        {list_to_hex(t_forged)}")

    print("\n--- STEP 4: Bank Verification ---")
    received_p, is_valid = aes_gcm_decrypt(
        c_forged, 
        key, 
        reused_iv, 
        aad=[], 
        mac=t_forged
    )

    if is_valid:
        print("[SUCCESS] Bank System: MAC verification PASSED! Signature is valid.")
        print(f"[SUCCESS] Bank executing instruction: '{received_p}'")
    else:
        print("[FAIL] Bank System: ERROR! Tampering detected, rejecting transaction.")

if __name__ == "__main__":
    iv_reused_attack_b()
