import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import hashlib
import os
import base64
import logging
import json
from datetime import datetime
import random
import math
from typing import Tuple, Dict, Any

# Настройка логирования
logging.basicConfig(
    filename=f"digital_signature_app_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


# --- Реализация криптографических алгоритмов ---

# Вспомогательные функции
def is_prime(n: int, k: int = 5) -> bool:
    """Проверка числа на простоту с помощью теста Миллера-Рабина"""
    if n <= 1 or n == 4:
        return False
    if n <= 3:
        return True

    # Найдем d и r такие, что n-1 = 2^r * d
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    # Проведем k тестов
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    """Генерация случайного простого числа размера bits бит"""
    while True:
        # Генерируем случайное число нужной длины
        p = random.getrandbits(bits)
        # Устанавливаем старший и младший биты в 1
        p |= (1 << bits - 1) | 1
        if is_prime(p):
            return p


def mod_inverse(a: int, m: int) -> int:
    """Вычисление мультипликативного обратного по модулю m"""
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError("Мультипликативное обратное не существует")
    else:
        return x % m


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Расширенный алгоритм Евклида для нахождения НОД и коэффициентов Безу"""
    if a == 0:
        return b, 0, 1
    else:
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y


# --- RSA ---
class RSA:
    @staticmethod
    def generate_keys(key_size: int = 2048) -> Dict[str, Any]:
        """Генерация пары ключей RSA"""
        # Генерируем два больших простых числа
        p = generate_prime(key_size // 2)
        q = generate_prime(key_size // 2)

        n = p * q
        phi = (p - 1) * (q - 1)

        # Выбираем открытую экспоненту e
        e = 65537 

        # Вычисляем закрытую экспоненту d
        d = mod_inverse(e, phi)

        # Публичный ключ (e, n)
        public_key = {"e": e, "n": n}

        # Приватный ключ (d, n)
        private_key = {"d": d, "n": n}

        return {
            "public_key": public_key,
            "private_key": private_key
        }

    @staticmethod
    def sign(message_hash: int, private_key: Dict[str, int]) -> int:
        """Подписание хеша сообщения с помощью приватного ключа RSA"""
        d = private_key["d"]
        n = private_key["n"]

        # Подпись - это message_hash^d mod n
        signature = pow(message_hash, d, n)
        return signature

    @staticmethod
    def verify(message_hash: int, signature: int, public_key: Dict[str, int]) -> bool:
        """Проверка подписи с помощью открытого ключа RSA"""
        e = public_key["e"]
        n = public_key["n"]

        # Вычисляем signature^e mod n, это должно быть равно message_hash
        result = pow(signature, e, n)
        return result == message_hash


# --- DSA ---
class DSA:
    @staticmethod
    def generate_parameters(L: int = 2048, N: int = 256) -> Dict[str, int]:
        """Генерация параметров DSA более эффективным способом"""
        # Генерация q (N-битное простое число)
        q = generate_prime(N)

        # Генерация p (так, чтобы p-1 делилось на q)
        # Ищем j такое, что p = q*j + 1 является простым
        j = 2  # Начинаем с j = 2
        bits_in_j = L - N  # Сколько битов нам нужно в j
        max_attempts = 1000  # Ограничение попыток

        for _ in range(max_attempts):
            # Генерируем случайное значение для j нужной длины
            j = random.getrandbits(bits_in_j)
            # Убедимся, что j имеет нужную битовую длину
            j |= (1 << (bits_in_j - 1))

            # Вычисляем p = q*j + 1
            p = q * j + 1

            # Проверяем, является ли p простым
            if is_prime(p):
                break
        else:
            # Если мы перебрали все попытки и не нашли подходящее p
            raise ValueError("Не удалось сгенерировать параметры DSA за отведенное количество попыток")

        # Находим h и g
        h = 2  # Начинаем с h = 2
        exp = (p - 1) // q
        g = 1
        max_h_attempts = 100

        for _ in range(max_h_attempts):
            g = pow(h, exp, p)
            if g > 1:
                break
            h += 1

        return {"p": p, "q": q, "g": g}

    @staticmethod
    def generate_keys(params: Dict[str, int]) -> Dict[str, Any]:
        """Генерация пары ключей DSA"""
        p = params["p"]
        q = params["q"]
        g = params["g"]

        # Генерация приватного ключа
        x = random.randint(1, q - 1)

        # Вычисление публичного ключа
        y = pow(g, x, p)

        public_key = {"y": y, "p": p, "q": q, "g": g}
        private_key = {"x": x, "p": p, "q": q, "g": g}

        return {
            "public_key": public_key,
            "private_key": private_key
        }

    """def sign(message_hash: int, private_key: Dict[str, int]) -> Tuple[int, int]:
        Подписание хеша сообщения с помощью приватного ключа DSA
        p = private_key["p"]
        q = private_key["q"]
        g = private_key["g"]
        x = private_key["x"]

        # Выбираем случайное k (1 < k < q)
        k = random.randint(1, q - 1)

        # Вычисляем r = (g^k mod p) mod q
        r = pow(g, k, p) % q

        # Вычисляем s = k^(-1) * (message_hash + x*r) mod q
        k_inv = mod_inverse(k, q)
        s = (k_inv * (message_hash + x * r)) % q

        return (r, s)"""

    @staticmethod
    def sign(message_hash: int, private_key: Dict[str, int]) -> Tuple[int, int]:
        """Подписание хеша сообщения с помощью приватного ключа DSA"""
        p = private_key["p"]
        q = private_key["q"]
        g = private_key["g"]
        x = private_key["x"]

        # Убедимся, что хеш меньше q
        message_hash = message_hash % q

        attempts = 0
        max_attempts = 100  # Предотвращение бесконечного цикла

        while attempts < max_attempts:
            attempts += 1

            # Выбираем случайное k (1 < k < q)
            k = random.randint(1, q - 1)
            if math.gcd(k, q) != 1:  # k должно быть взаимно просто с q
                continue

            # Вычисляем r = (g^k mod p) mod q
            r = pow(g, k, p) % q
            if r == 0:  # r не должно быть 0
                continue

            # Вычисляем s = k^(-1) * (message_hash + x*r) mod q
            try:
                k_inv = mod_inverse(k, q)
                s = (k_inv * (message_hash + x * r)) % q
                if s == 0:  # s не должно быть 0
                    continue
                return (r, s)
            except ValueError:
                continue

        raise RuntimeError("Не удалось создать подпись DSA после нескольких попыток")

    # Improved DSA verify method
    @staticmethod
    def verify(message_hash: int, signature: Tuple[int, int] or list, public_key: Dict[str, int]) -> bool:
        """Проверка подписи с помощью открытого ключа DSA"""
        # Convert list to tuple if needed
        if isinstance(signature, list) and len(signature) == 2:
            signature = tuple(signature)

        if not isinstance(signature, tuple) or len(signature) != 2:
            return False

        r, s = signature
        p = public_key["p"]
        q = public_key["q"]
        g = public_key["g"]
        y = public_key["y"]

        # Проверяем, что 0 < r < q и 0 < s < q
        if r <= 0 or r >= q or s <= 0 or s >= q:
            return False

        # Убедимся, что хеш меньше q
        message_hash = message_hash % q

        try:
            # Вычисляем w = s^(-1) mod q
            w = mod_inverse(s, q)

            # Вычисляем u1 = (message_hash * w) mod q
            u1 = (message_hash * w) % q

            # Вычисляем u2 = (r * w) mod q
            u2 = (r * w) % q

            # Вычисляем v = ((g^u1 * y^u2) mod p) mod q
            v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q

            # Подпись верна, если v = r
            return v == r
        except Exception:
            return False



# --- ElGamal ---
class ElGamal:
    @staticmethod
    def generate_keys(key_size: int = 2048) -> Dict[str, Any]:
        """Генерация пары ключей ElGamal"""
        # Генерация большого простого числа p
        p = generate_prime(key_size)

        # Выбор генератора g группы Z_p^*
        g = random.randint(2, p - 2)

        # Выбор секретного ключа x
        x = random.randint(2, p - 2)

        # Вычисление открытого ключа y = g^x mod p
        y = pow(g, x, p)

        public_key = {"p": p, "g": g, "y": y}
        private_key = {"p": p, "g": g, "x": x}

        return {
            "public_key": public_key,
            "private_key": private_key
        }

    @staticmethod
    def sign(message_hash: int, private_key: Dict[str, int]) -> Tuple[int, int]:
        """Подписание хеша сообщения с помощью приватного ключа ElGamal"""
        p = private_key["p"]
        g = private_key["g"]
        x = private_key["x"]

        # Выбираем случайное k взаимно простое с p-1
        p_1 = p - 1
        while True:
            k = random.randint(2, p_1 - 1)
            if math.gcd(k, p_1) == 1:
                break

        # Вычисляем r = g^k mod p
        r = pow(g, k, p)

        # Вычисляем s = k^(-1) * (message_hash - x*r) mod (p-1)
        k_inv = mod_inverse(k, p_1)
        s = (k_inv * (message_hash - x * r)) % p_1

        return (r, s)

    @staticmethod
    def verify(message_hash: int, signature: Tuple[int, int], public_key: Dict[str, int]) -> bool:
        """Проверка подписи с помощью открытого ключа ElGamal"""
        r, s = signature
        p = public_key["p"]
        g = public_key["g"]
        y = public_key["y"]

        # Проверяем, что 0 < r < p
        if r <= 0 or r >= p:
            return False

        # Вычисляем левую часть: g^message_hash mod p
        left = pow(g, message_hash, p)

        # Вычисляем правую часть: (r^s * y^r) mod p
        right = (pow(r, s, p) * pow(y, r, p)) % p

        # Подпись верна, если левая часть = правой части
        return left == right


class DigitalSignatureApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DigitalSignatureAPP")
        self.root.geometry("800x600")
        self.root.resizable(True, True)

        # Переменные для хранения выбранных алгоритмов
        self.signature_alg = tk.StringVar(value="RSA")
        self.hash_alg = tk.StringVar(value="SHA-256")

        # Переменные для хранения ключей
        self.private_key = None
        self.public_key = None
        self.key_params = None  # Для DSA
        self.signature = None

        # Создание основного интерфейса
        self.create_widgets()

        logging.info("Приложение запущено")

    def create_widgets(self):
        # Создание вкладок
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Фрейм для выбора алгоритмов
        alg_frame = ttk.LabelFrame(main_frame, text="Выбор алгоритмов", padding="10")
        alg_frame.pack(fill=tk.X, pady=5)

        # Выбор алгоритма ЭЦП
        ttk.Label(alg_frame, text="Алгоритм подписи:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        signature_combo = ttk.Combobox(alg_frame, textvariable=self.signature_alg, state="readonly")
        signature_combo['values'] = ("RSA", "ElGamal", "DSA")
        signature_combo.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)

        # Выбор алгоритма хеширования
        ttk.Label(alg_frame, text="Алгоритм хеширования:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        hash_combo = ttk.Combobox(alg_frame, textvariable=self.hash_alg, state="readonly")
        hash_combo['values'] = ("SHA-256", "SHA-384", "SHA-512")
        hash_combo.grid(row=0, column=3, sticky=tk.W, padx=5, pady=5)

        # Фрейм для генерации ключей
        keys_frame = ttk.LabelFrame(main_frame, text="Генерация и управление ключами", padding="10")
        keys_frame.pack(fill=tk.X, pady=5)

        ttk.Button(keys_frame, text="Сгенерировать ключи", command=self.generate_keys).grid(row=0, column=0, padx=5,
                                                                                            pady=5)
        ttk.Button(keys_frame, text="Сохранить открытый ключ", command=lambda: self.save_key("public")).grid(row=0,
                                                                                                             column=1,
                                                                                                             padx=5,
                                                                                                             pady=5)
        ttk.Button(keys_frame, text="Сохранить закрытый ключ", command=lambda: self.save_key("private")).grid(row=0,
                                                                                                              column=2,
                                                                                                              padx=5,
                                                                                                              pady=5)
        ttk.Button(keys_frame, text="Загрузить открытый ключ", command=lambda: self.load_key("public")).grid(row=1,
                                                                                                             column=1,
                                                                                                             padx=5,
                                                                                                             pady=5)
        ttk.Button(keys_frame, text="Загрузить закрытый ключ", command=lambda: self.load_key("private")).grid(row=1,
                                                                                                              column=2,
                                                                                                              padx=5,
                                                                                                              pady=5)

        # Фрейм для отображения ключей
        keys_display_frame = ttk.LabelFrame(main_frame, text="Отображение ключей", padding="10")
        keys_display_frame.pack(fill=tk.X, pady=5)

        ttk.Label(keys_display_frame, text="Открытый ключ:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.public_key_text = scrolledtext.ScrolledText(keys_display_frame, width=40, height=3)
        self.public_key_text.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W + tk.E)

        ttk.Label(keys_display_frame, text="Закрытый ключ:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.private_key_text = scrolledtext.ScrolledText(keys_display_frame, width=40, height=3)
        self.private_key_text.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W + tk.E)

        # Создание и проверка подписи
        operations_frame = ttk.LabelFrame(main_frame, text="Операции с подписью", padding="10")
        operations_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        # Вкладки для подписания и проверки
        notebook = ttk.Notebook(operations_frame)
        notebook.pack(fill=tk.BOTH, expand=True)

        # Вкладка подписания
        sign_frame = ttk.Frame(notebook, padding="10")
        notebook.add(sign_frame, text="Создание подписи")

        ttk.Label(sign_frame, text="Сообщение для подписи:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.message_to_sign = scrolledtext.ScrolledText(sign_frame, width=40, height=5)
        self.message_to_sign.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W + tk.E)

        ttk.Button(sign_frame, text="Подписать сообщение", command=self.sign_message).grid(row=1, column=1, padx=5,
                                                                                           pady=5, sticky=tk.E)

        ttk.Label(sign_frame, text="Созданная подпись:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.signature_text = scrolledtext.ScrolledText(sign_frame, width=40, height=5)
        self.signature_text.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W + tk.E)

        ttk.Button(sign_frame, text="Сохранить подпись", command=self.save_signature).grid(row=3, column=1, padx=5,
                                                                                           pady=5, sticky=tk.E)

        # Вкладка проверки
        verify_frame = ttk.Frame(notebook, padding="10")
        notebook.add(verify_frame, text="Проверка подписи")

        ttk.Label(verify_frame, text="Исходное сообщение:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.message_to_verify = scrolledtext.ScrolledText(verify_frame, width=40, height=5)
        self.message_to_verify.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W + tk.E)

        ttk.Label(verify_frame, text="Подпись для проверки:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.verify_signature_text = scrolledtext.ScrolledText(verify_frame, width=40, height=5)
        self.verify_signature_text.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W + tk.E)

        ttk.Button(verify_frame, text="Загрузить подпись", command=self.load_signature).grid(row=2, column=0, padx=5,
                                                                                             pady=5)
        ttk.Button(verify_frame, text="Проверить подпись", command=self.verify_signature).grid(row=2, column=1, padx=5,
                                                                                               pady=5, sticky=tk.E)

        # Результат проверки
        ttk.Label(verify_frame, text="Результат проверки:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        self.verify_result = ttk.Label(verify_frame, text="")
        self.verify_result.grid(row=3, column=1, sticky=tk.W, padx=5, pady=5)

    def generate_keys(self):
        try:
            alg = self.signature_alg.get()
            logging.info(f"Генерация ключей для алгоритма {alg}")

            # Для демонстрации используем небольшие размеры ключей
            # В реальном приложении следует использовать размеры не менее 2048 бит
            key_size = 512  # Тут можно увеличить, но генерация будет дольше

            if alg == "RSA":
                keys = RSA.generate_keys(key_size)
                self.private_key = keys["private_key"]
                self.public_key = keys["public_key"]
            elif alg == "DSA":
                # Для DSA сначала генерируем параметры
                self.key_params = DSA.generate_parameters(L=key_size, N=256)
                keys = DSA.generate_keys(self.key_params)
                self.private_key = keys["private_key"]
                self.public_key = keys["public_key"]
            elif alg == "ElGamal":
                keys = ElGamal.generate_keys(key_size)
                self.private_key = keys["private_key"]
                self.public_key = keys["public_key"]

            # Отображение ключей в интерфейсе
            self.private_key_text.delete(1.0, tk.END)
            self.private_key_text.insert(tk.END, json.dumps(self.private_key, indent=2))

            self.public_key_text.delete(1.0, tk.END)
            self.public_key_text.insert(tk.END, json.dumps(self.public_key, indent=2))

            #messagebox.showinfo("Успех", f"Ключи для алгоритма {alg} успешно сгенерированы")
            logging.info(f"Ключи для алгоритма {alg} успешно сгенерированы")

        except Exception as e:
            #messagebox.showerror("Ошибка", f"Не удалось сгенерировать ключи: {str(e)}")
            logging.error(f"Ошибка при генерации ключей: {str(e)}")

    def save_key(self, key_type):
        if key_type == "public" and self.public_key:
            key_data = json.dumps(self.public_key, indent=2)
            file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
            if file_path:
                with open(file_path, 'w') as f:
                    f.write(key_data)
                logging.info(f"Открытый ключ сохранен в {file_path}")
                #messagebox.showinfo("Успех", "Открытый ключ успешно сохранен")
        elif key_type == "private" and self.private_key:
            key_data = json.dumps(self.private_key, indent=2)
            file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
            if file_path:
                with open(file_path, 'w') as f:
                    f.write(key_data)
                logging.info(f"Закрытый ключ сохранен в {file_path}")
                #messagebox.showinfo("Успех", "Закрытый ключ успешно сохранен")
       # else:
            #messagebox.showwarning("Предупреждение", "Сначала необходимо сгенерировать ключи")

    def load_key(self, key_type):
        file_path = filedialog.askopenfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])

        if not file_path:
            return

        try:
            with open(file_path, 'r') as f:
                key_data = json.load(f)

            if key_type == "public":
                self.public_key = key_data
                self.public_key_text.delete(1.0, tk.END)
                self.public_key_text.insert(tk.END, json.dumps(key_data, indent=2))
                logging.info(f"Открытый ключ загружен из {file_path}")
                #messagebox.showinfo("Успех", "Открытый ключ успешно загружен")
            else:
                self.private_key = key_data
                self.private_key_text.delete(1.0, tk.END)
                self.private_key_text.insert(tk.END, json.dumps(key_data, indent=2))
                logging.info(f"Закрытый ключ загружен из {file_path}")
                #messagebox.showinfo("Успех", "Закрытый ключ успешно загружен")

                # Для DSA или ElGamal пытаемся также вычислить публичный ключ
                alg = self.signature_alg.get()
                if alg == "DSA" and "p" in key_data and "q" in key_data and "g" in key_data:
                    self.key_params = {"p": key_data["p"], "q": key_data["q"], "g": key_data["g"]}

        except Exception as e:
            #messagebox.showerror("Ошибка", f"Не удалось загрузить ключ: {str(e)}")
            logging.error(f"Ошибка при загрузке ключа: {str(e)}")

    def compute_hash(self, message: str) -> int:
        """Вычисление хеша сообщения с использованием выбранного алгоритма"""
        hash_alg = self.hash_alg.get()

        if hash_alg == "SHA-256":
            hash_obj = hashlib.sha256()
        elif hash_alg == "SHA-384":
            hash_obj = hashlib.sha384()
        elif hash_alg == "SHA-512":
            hash_obj = hashlib.sha512()
        else:
            hash_obj = hashlib.sha256()

        hash_obj.update(message.encode('utf-8'))
        hash_digest = hash_obj.digest()

        # Преобразуем хеш в целое число
        hash_int = int.from_bytes(hash_digest, byteorder='big')

        # Обработка для разных алгоритмов
        alg = self.signature_alg.get()

        if alg == "DSA" and self.private_key and 'q' in self.private_key:
            # Для DSA хеш должен быть меньше q
            q = self.private_key['q']
            hash_int = hash_int % q
        elif alg == "DSA" and self.public_key and 'q' in self.public_key:
            # При проверке также нужно модулировать хеш
            q = self.public_key['q']
            hash_int = hash_int % q
        elif alg == "RSA" and self.private_key and 'n' in self.private_key:
            # Для RSA ограничиваем хеш размером модуля n
            n = self.private_key['n']
            hash_int = hash_int % n

        return hash_int

    def sign_message(self):
        if not self.private_key:
            #messagebox.showwarning("Предупреждение", "Сначала необходимо сгенерировать или загрузить закрытый ключ")
            return

        message = self.message_to_sign.get("1.0", tk.END).strip()
        if not message:
           # messagebox.showwarning("Предупреждение", "Введите сообщение для подписи")
            return

        try:
            alg = self.signature_alg.get()
            hash_int = self.compute_hash(message)

            logging.info(f"Подписание сообщения алгоритмом {alg}")

            if alg == "RSA":
                self.signature = RSA.sign(hash_int, self.private_key)
            elif alg == "DSA":
                self.signature = DSA.sign(hash_int, self.private_key)
                # Make sure it's displayed correctly
                self.signature_text.delete(1.0, tk.END)
                self.signature_text.insert(tk.END, json.dumps(self.signature))
            elif alg == "ElGamal":
                self.signature = ElGamal.sign(hash_int, self.private_key)

            # Отображение подписи в интерфейсе
            self.signature_text.delete(1.0, tk.END)
            self.signature_text.insert(tk.END, json.dumps(self.signature))

            #messagebox.showinfo("Успех", "Сообщение успешно подписано")
            logging.info("Сообщение успешно подписано")

        except Exception as e:
           # messagebox.showerror("Ошибка", f"Не удалось подписать сообщение: {str(e)}")
            logging.error(f"Ошибка при подписании сообщения: {str(e)}")

    def save_signature(self):
        if not self.signature:
            #messagebox.showwarning("Предупреждение", "Сначала необходимо создать подпись")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".sign", filetypes=[("Signature files", "*.sign")])

        if file_path:
            try:
                with open(file_path, 'w') as f:
                    json.dump({
                        "algorithm": self.signature_alg.get(),
                        "hash_algorithm": self.hash_alg.get(),
                        "signature": self.signature,
                        "message": self.message_to_sign.get("1.0", tk.END).strip()
                    }, f, indent=2)

                logging.info(f"Подпись сохранена в {file_path}")
                #messagebox.showinfo("Успех", "Подпись успешно сохранена")

            except Exception as e:
               # messagebox.showerror("Ошибка", f"Не удалось сохранить подпись: {str(e)}")
                logging.error(f"Ошибка при сохранении подписи: {str(e)}")

    def load_signature(self):
        file_path = filedialog.askopenfilename(defaultextension=".sign", filetypes=[("Signature files", "*.sign")])

        if not file_path:
            return

        try:
            with open(file_path, 'r') as f:
                signature_data = json.load(f)

            # Установка алгоритмов из файла подписи
            if "algorithm" in signature_data:
                self.signature_alg.set(signature_data["algorithm"])
            if "hash_algorithm" in signature_data:
                self.hash_alg.set(signature_data["hash_algorithm"])

            # Загрузка подписи и сообщения
            if "signature" in signature_data:
                self.verify_signature_text.delete(1.0, tk.END)
                self.verify_signature_text.insert(tk.END, json.dumps(signature_data["signature"]))

            if "message" in signature_data:
                self.message_to_verify.delete(1.0, tk.END)
                self.message_to_verify.insert(tk.END, signature_data["message"])

            logging.info(f"Подпись загружена из {file_path}")
           # messagebox.showinfo("Успех", "Подпись успешно загружена")

        except Exception as e:
           # messagebox.showerror("Ошибка", f"Не удалось загрузить подпись: {str(e)}")
            logging.error(f"Ошибка при загрузке подписи: {str(e)}")

    def verify_signature(self):
        if not self.public_key:
           # messagebox.showwarning("Предупреждение", "Сначала необходимо загрузить открытый ключ")
            return

        message = self.message_to_verify.get("1.0", tk.END).strip()
        if not message:
            #messagebox.showwarning("Предупреждение", "Введите сообщение для проверки")
            return

        signature_text = self.verify_signature_text.get("1.0", tk.END).strip()
        if not signature_text:
           # messagebox.showwarning("Предупреждение", "Введите подпись для проверки")
            return

        try:
            # Преобразуем подпись из текста в объект Python
            signature = json.loads(signature_text)

            # Вычисляем хеш сообщения
            hash_int = self.compute_hash(message)

            alg = self.signature_alg.get()
            logging.info(f"Проверка подписи алгоритмом {alg}")

            is_valid = False
            if alg == "RSA":
                is_valid = RSA.verify(hash_int, signature, self.public_key)
            # Handle the case where the signature could be a list (from JSON) instead of tuple
            # In the verify_signature method
            elif alg == "DSA":
                # Ensure the signature is in the correct format
                if isinstance(signature, list) and len(signature) == 2:
                    signature = tuple(signature)  # Convert list to tuple
                is_valid = DSA.verify(hash_int, signature, self.public_key)

            elif alg == "ElGamal":
                is_valid = ElGamal.verify(hash_int, signature, self.public_key)

            # Отображение результата проверки
            if is_valid:
                self.verify_result.config(text="Подпись верна", foreground="green")
                logging.info("Проверка подписи: подпись верна")
            else:
                self.verify_result.config(text="Подпись неверна!", foreground="red")
                logging.info("Проверка подписи: подпись неверна")

        except Exception as e:
          #  messagebox.showerror("Ошибка", f"Не удалось проверить подпись: {str(e)}")
            logging.error(f"Ошибка при проверке подписи: {str(e)}")
            self.verify_result.config(text=f"Ошибка: {str(e)}", foreground="red")

    # Запуск приложения
if __name__ == "__main__":
    root = tk.Tk()
    app = DigitalSignatureApp(root)
    root.mainloop()