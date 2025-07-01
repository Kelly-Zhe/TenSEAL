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
    
mod_p = context.get_modulusP()
print(f"[+] Modulus P (L={len(mod_p)}):")
for i, p in enumerate(mod_p):
    print(f"  P[{i}] = {p}")

# 3. 加密一个向量
plain_vec = [1.1, 2.2, 3.3, 4.4]
vec = ts.ckks_vector(context, plain_vec)

# 4. 获取密文的系数值（uint64）
ciph_coeffs = vec.get_ckks_ciphertext_values()
print(f"[+] Ciphertext slot count = {len(ciph_coeffs)} polys")

#5. 构造一个新的ckksvector from raw data
vec+=vec
ciph_coeffs2 = vec.get_ckks_ciphertext_values()

parms_id = vec.parms_id()
scale = 2**40
ciph_coeffs2 = np.array(ciph_coeffs2, dtype=np.uint64).flatten().tolist()
test_vec = ts.CKKSVector.from_raw(context, ciph_coeffs2, parms_id, scale,4)

res = test_vec.decrypt()

# 6. 获取 relin keys（uint64_t）
rk_vals = context.get_relin_key_values()
print(f"[+] Relin keys count = {len(rk_vals)} polys")
# print(f"    First relin poly preview: {rk_vals[0][:10]}")

# 6. 获取 galois keys（uint64_t）

import tenseal.sealapi as sealapi
context.generate_galois_keys()
seal_ctx = context.seal_context().data
keygen = sealapi.KeyGenerator(seal_ctx)
idx = sealapi.GaloisKeys.get_index(7)
keygen = sealapi.KeyGenerator(context.seal_context().data)
galois_keys = sealapi.GaloisKeys()
keygen.create_galois_keys([idx], galois_keys)

# Step 4: 访问 raw_data
if galois_keys.has_key(idx):
    raw_data = galois_keys.get_raw_data(idx, seal_ctx)
    print("Got raw data shape:")
    print(f"#keys: {len(raw_data)}")
    print(f"#modulus layers: {len(raw_data[0])}")
    print(f"#polys: {len(raw_data[0][0])}")
    print(f"#coeffs: {len(raw_data[0][0][0])}")
else:
    print("Galois key not found!")




# print(f"[+] Galois keys count = {len(gk_vals)} polys")
# print(f"    First galois poly preview: {gk_vals[0][:10]}")
# import tenseal.sealapi as sealapi
# ctx_data = context.seal_context().data.key_context_data()
# parms = ctx_data.parms()
# idx = sealapi.GaloisKeys.get_index(7)
# keygen = sealapi.KeyGenerator(context.seal_context().data)
# galois_keys = sealapi.GaloisKeys()
# keygen.create_galois_keys([idx], galois_keys)
# pubkey = galois_keys.key(idx)[0]


print("done")