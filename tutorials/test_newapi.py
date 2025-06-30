# import sys
# sys.path.insert(0, "/home/wwz/wwz_local/projects/project_public/TenSEAL/build/lib.linux-x86_64-3.10")

import tenseal as ts
import numpy as np


print(dir(ts.context))

# 1. 创建 CKKS 上下文
context = ts.context(
    ts.SCHEME_TYPE.CKKS,
    poly_modulus_degree=8192,
    coeff_mod_bit_sizes=[60, 40, 40, 40]  # 总共 L=4
)
context.global_scale = pow(2, 40)
context.generate_galois_keys()
context.generate_relin_keys()

# 2. 获取 Q/P 链
mod_q = context.get_modulusQ()
print(f"[+] Modulus Q (L={len(mod_q)}):")
for i, q in enumerate(mod_q):
    print(f"  Q[{i}] = {q}")
#
# # 若你定义了 get_modulusP，才调用
# if hasattr(ts, "get_modulusP"):
#     mod_p = ts.get_modulusP(context)
#     print(f"[+] Modulus P (count={len(mod_p)}): {mod_p}")
# else:
#     print("[!] get_modulusP not defined in your bindings.")
#
# 3. 加密一个向量
plain_vec = [1.1, 2.2, 3.3, 4.4]
vec = ts.ckks_vector(context, plain_vec)

# 4. 获取密文的系数值（uint64）
ciph_coeffs = vec.get_ckks_ciphertext_values()
print(f"[+] Ciphertext slot count = {len(ciph_coeffs)} polys")

vec+=vec
ciph_coeffs2 = vec.get_ckks_ciphertext_values()

parms_id = vec.parms_id()
scale = 2**40
ciph_coeffs2 = np.array(ciph_coeffs2, dtype=np.uint64).flatten().tolist()
test_vec = ts.CKKSVector.from_raw(context, ciph_coeffs2, parms_id, scale,4)

res = test_vec.decrypt()

#
# 5. 获取 relin keys（uint64_t）
rk_vals = context.get_relin_key_values()
print(f"[+] Relin keys count = {len(rk_vals)} polys")
print(f"    First relin poly preview: {rk_vals[0][:10]}")

# 6. 获取 galois keys（uint64_t）
gk_vals = context.get_galois_key_values()
print(f"[+] Galois keys count = {len(gk_vals)} polys")
print(f"    First galois poly preview: {gk_vals[0][:10]}")