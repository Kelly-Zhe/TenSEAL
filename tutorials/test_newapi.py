# import sys
# sys.path.insert(0, "/home/wwz/wwz_local/projects/project_public/TenSEAL/build/lib.linux-x86_64-3.10")

import tenseal as ts
import numpy as np


print(dir(ts.context))

# 1. 创建 CKKS 上下文
context = ts.context(
    ts.SCHEME_TYPE.CKKS,
    poly_modulus_degree=16384,
    coeff_mod_bit_sizes=[60, 59, 59, 59]  # 总共 L=4
)
context.global_scale = pow(2, 59)
context.generate_galois_keys()
context.generate_relin_keys()

# 2. 获取 Q/P 链
mod_q, mod_p = context.get_modulus()
print(f"[+] Modulus Q (L={len(mod_q)}):")
for i, q in enumerate(mod_q):
    print(f"  Q[{i}] = {q}")

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
scale = 2**59
ciph_coeffs2 = np.array(ciph_coeffs2, dtype=np.uint64).flatten().tolist()
test_vec = ts.CKKSVector.from_raw(context, ciph_coeffs2, parms_id, scale,4)

res = test_vec.decrypt()

# 6. 获取 relin keys（uint64_t）
rk_vals0 = context.get_relin_key_values()
rk_vals = context.get_eval_mult_key()
print("Got raw data shape:")
print(f"#polys: {len(rk_vals)}")
print(f"#keys: {len(rk_vals[0])}")
# print(f"#modulus: {len(rk_vals[0][0])}")
# print(f"#coeffs: {len(rk_vals[0][0][0])}")

# 6. 获取 galois keys（uint64_t）
import tenseal.sealapi.util as util
import tenseal.sealapi as sealapi
logN=14
rotIndex_list=[-1]
slot_conversion_rot_index = [1 << i for i in range(8, logN-1)]  # logN 例如是 13
rotIndex_list = slot_conversion_rot_index if rotIndex_list is None else rotIndex_list + slot_conversion_rot_index
galois_tool = util.GaloisTool(14)
# def get_autoIndex(step):
#     return pow(5, 2 * step + 1, 2 * 2**14)

# print(get_autoIndex(1), get_autoIndex(-1), get_autoIndex(256))
# print(galois_tool.get_elt_from_step(1), galois_tool.get_elt_from_step(-1), galois_tool.get_elt_from_step(256))


autoIdx_list = [galois_tool.get_elt_from_step(step) for step in rotIndex_list]

gk_vals = context.get_eval_rotate_key_by_indices(autoIdx_list)

# seal_ctx = context.seal_context().data
# keygen = sealapi.KeyGenerator(seal_ctx)
# galois_keys = sealapi.GaloisKeys()
# keygen.create_galois_keys(autoIdx_list, galois_keys)
# raw_data = []
# for idx in autoIdx_list:
#     raw_data.append(galois_keys.get_raw_data(idx, seal_ctx))
autoIdx2rotIdx_map = dict(zip(autoIdx_list, rotIndex_list))

print("Got raw data shape:")
print(f"#keys: {len(gk_vals)}")
for galois_element, B, A in gk_vals:
    print(f"B size: {len(B)}, A size: {len(A)}")
# print(f"#modulus layers: {len(gk_vals[0])}")
# print(f"#modulus: {len(gk_vals[1][0])}")
# print(f"#polys: {len(gk_vals[0][0][0])}")
# print(f"#coeffs: {len(gk_vals[0][0][0][0])}")

# import tenseal.sealapi as sealapi
# seal_ctx = context.seal_context().data
# evaluator = sealapi.Evaluator(seal_ctx)
# test_vec = [1.1, 2.2, 3.3, 4.4]
# encrypted = ts.ckks_vector(context, plain_vec)
# # out = sealapi.Ciphertext(ctx)
# evaluator.rotate_vector_inplace(encrypted.ciphertext, -1, sealapi.GaloisKeys())
# keygen = sealapi.KeyGenerator(seal_ctx)
# idx = sealapi.GaloisKeys.get_index(7)
# keygen = sealapi.KeyGenerator(seal_ctx)
# galois_keys = sealapi.GaloisKeys()
# keygen.create_galois_keys([idx], galois_keys)

v1 = ts.ckks_vector(context, [1.0, 2.0])
v2 = ts.ckks_vector(context, [3.0, 4.0])
v3 = v1 * v2 

# # 向左旋转 1 位
# rotated = vec.rotate(-1)

# # 解密查看结果
# print(rotated.decrypt())  # 输出: [4.0, 1.0, 2.0, 3.0]


print("done")