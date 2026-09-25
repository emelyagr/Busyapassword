import os
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
import getpass
import sys

# Автор проекта: Емельянов Григорий Андреевич @emelyagr https://github.com/emelyagr
# Author of the project: Emelyanov Grigory Andreevich @emelyagr https://github.com/emelyagr -->

class PasswordManager:
    def __init__(self, master_password):
        self.ph = PasswordHasher()
        self.db_file = "passwords.json"
        self.db = {}
        self.master_hash = None
        self.salt = None
        self.cipher = None
        self.master_password = master_password
        
        self.load_db_metadata()
        
        if self.salt is None:
            self.salt = os.urandom(32)
        
        self.key = self.derive_key(master_password)
        self.cipher = Fernet(self.key)
        
        self.decrypt_db()
        self.verify_master_password(master_password)
    
    def derive_key(self, password):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=600000
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    def verify_master_password(self, master_password):
        if self.master_hash:
            try:
                self.ph.verify(self.master_hash, master_password)
                print("✅ Доступ разрешен!")
            except VerificationError:
                print("\n❌ НЕВЕРНЫЙ МАСТЕР-ПАРОЛЬ!")
                print("Программа будет закрыта...")
                sys.exit(1)
    
    def load_db_metadata(self):
        try:
            with open(self.db_file, 'r') as f:
                encrypted_data = f.read()
                if encrypted_data:
                    data = json.loads(encrypted_data)
                    self.salt = base64.b64decode(data['salt'])
                else:
                    self.salt = os.urandom(32)
        except (FileNotFoundError, json.JSONDecodeError):
            self.salt = os.urandom(32)
        except Exception as e:
            print(f"⚠️ Ошибка загрузки метаданных: {e}")
            self.salt = os.urandom(32)
    
    def decrypt_db(self):
        try:
            with open(self.db_file, 'r') as f:
                encrypted_data = f.read()
                if encrypted_data:
                    data = json.loads(encrypted_data)
                    decrypted_json = self.cipher.decrypt(data['data'].encode()).decode()
                    db_data = json.loads(decrypted_json)
                    self.db = db_data.get('passwords', {})
                    self.master_hash = db_data.get('master_hash')
                else:
                    self.db = {}
                    self.master_hash = None
        except (FileNotFoundError, json.JSONDecodeError):
            self.db = {}
            self.master_hash = None
        except Exception as e:
            print("⚠️ Ошибка расшифровки базы данных")
            self.db = {}
            self.master_hash = None
    
    def save_db(self):
        if self.cipher is None:
            print("❌ Ошибка: шифр не инициализирован")
            return
        
        db_data = {
            'passwords': self.db,
            'master_hash': self.master_hash
        }
        
        encrypted_data = {
            'data': self.cipher.encrypt(json.dumps(db_data).encode()).decode(),
            'salt': base64.b64encode(self.salt).decode()
        }
        
        with open(self.db_file, 'w') as f:
            json.dump(encrypted_data, f)
    
    def change_master_password(self, old_password, new_password):
        """Безопасная смена мастер-пароля"""
        # Проверяем старый пароль
        if self.master_hash is not None:
            try:
                self.ph.verify(self.master_hash, old_password)
            except VerificationError:
                print("❌ Неверный старый пароль!")
                return False
        
        # Проверяем новый пароль
        if len(new_password) < 8:
            print("❌ Пароль должен содержать минимум 8 символов!")
            return False
        
        # 1. СОЗДАЕМ ВРЕМЕННЫЙ КЛЮЧ ИЗ СТАРОГО ПАРОЛЯ
        old_key = self.derive_key(old_password)
        old_cipher = Fernet(old_key)
        
        # 2. СОЗДАЕМ НОВЫЙ КЛЮЧ
        new_salt = os.urandom(32)
        new_key = self.derive_key_with_salt(new_password, new_salt)
        new_cipher = Fernet(new_key)
        
        # 3. РАСШИФРОВЫВАЕМ ВСЕ ДАННЫЕ СТАРЫМ КЛЮЧОМ
        try:
            with open(self.db_file, 'r') as f:
                encrypted_data = f.read()
                if encrypted_data:
                    data = json.loads(encrypted_data)
                    # Расшифровываем старым ключом
                    decrypted_json = old_cipher.decrypt(data['data'].encode()).decode()
                    db_data = json.loads(decrypted_json)
                    old_passwords = db_data.get('passwords', {})
                else:
                    old_passwords = {}
        except Exception as e:
            print(f"❌ Ошибка расшифровки старым ключом: {e}")
            return False
        
        # 4. ПЕРЕШИФРОВЫВАЕМ КАЖДЫЙ ПАРОЛЬ НОВЫМ КЛЮЧОМ
        new_passwords = {}
        for service, entry in old_passwords.items():
            try:
                # Расшифровываем пароль старым ключом
                password = old_cipher.decrypt(entry['encrypted'].encode()).decode()
                
                # Шифруем новым ключом
                new_passwords[service] = {
                    'username': entry['username'],
                    'password_hash': self.ph.hash(password),
                    'encrypted': new_cipher.encrypt(password.encode()).decode()
                }
            except Exception as e:
                print(f"⚠️ Ошибка перешифровки пароля для '{service}': {e}")
                return False
        
        # 5. СОХРАНЯЕМ С НОВЫМ КЛЮЧОМ
        self.db = new_passwords
        self.salt = new_salt
        self.key = new_key
        self.cipher = new_cipher
        self.master_hash = self.ph.hash(new_password)
        
        db_data = {
            'passwords': self.db,
            'master_hash': self.master_hash
        }
        
        encrypted_data = {
            'data': self.cipher.encrypt(json.dumps(db_data).encode()).decode(),
            'salt': base64.b64encode(self.salt).decode()
        }
        
        with open(self.db_file, 'w') as f:
            json.dump(encrypted_data, f)
        
        print(f"✅ Мастер-пароль успешно изменен! Перешифровано {len(self.db)} паролей.")
        return True
    
    def derive_key_with_salt(self, password, salt):
        """Создание ключа с указанной солью"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600000
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    def add_password(self, service, username, password):
        self.db[service] = {
            'username': username,
            'password_hash': self.ph.hash(password),
            'encrypted': self.cipher.encrypt(password.encode()).decode()
        }
        self.save_db()
        print(f"✅ Пароль для '{service}' успешно добавлен!")
    
    def get_password(self, service):
        if service not in self.db:
            print(f"❌ Сервис '{service}' не найден!")
            return None
        
        entry = self.db[service]
        try:
            password = self.cipher.decrypt(entry['encrypted'].encode()).decode()
            self.ph.verify(entry['password_hash'], password)
            return {
                'username': entry['username'],
                'password': password
            }
        except (VerificationError, Exception) as e:
            print(f"❌ Ошибка верификации - возможно, данные были изменены!")
            return None
    
    def list_services(self):
        return list(self.db.keys())
    
    def delete_password(self, service):
        if service in self.db:
            del self.db[service]
            self.save_db()
            print(f"✅ Пароль для '{service}' удален!")
        else:
            print(f"❌ Сервис '{service}' не найден!")

def show_menu():
    print("\n" + "="*50)
    print("🔐 Менеджер паролей Busyapassword =^◕⩊◕^=")
    print("="*50)
    print("1️⃣  Добавить новый пароль")
    print("2️⃣  Получить пароль (выбор из списка)")
    print("3️⃣  Показать все сервисы")
    print("4️⃣  Удалить пароль")
    print("5️⃣  Сменить мастер-пароль")
    print("6️⃣  Мяу-выход 🐈‍⬛")
    print("="*50)

# Автор проекта: Емельянов Григорий Андреевич @emelyagr https://github.com/emelyagr
# Author of the project: Emelyanov Grigory Andreevich @emelyagr https://github.com/emelyagr -->

def select_service(pm, action="получения"):
    services = pm.list_services()
    if not services:
        print("📭 Нет сохраненных паролей!")
        return None
    
    print(f"\n📋 Выберите сервис для {action}:")
    for i, service in enumerate(services, 1):
        print(f"  {i}. {service}")
    print("  0. Отмена")
    
    try:
        choice = int(input("\nВведите номер: "))
        if choice == 0:
            return None
        if 1 <= choice <= len(services):
            return services[choice-1]
        else:
            print("❌ Неверный номер!")
            return None
    except ValueError:
        print("❌ Введите число!")
        return None

def main():
    print("🔐 МЕНЕДЖЕР ПАРОЛЕЙ")
    print("="*40)
    
    master_pass = getpass.getpass("Введите мастер-пароль: ")
    
    if not os.path.exists("passwords.json"):
        print("🆕 Первый запуск! Создание новой базы...")
        confirm = getpass.getpass("Повторите мастер-пароль: ")
        if master_pass != confirm:
            print("❌ Пароли не совпадают!")
            print("Программа будет закрыта...")
            sys.exit(1)
    
    try:
        pm = PasswordManager(master_pass)
    except Exception as e:
        print(f"❌ Ошибка: {e}")
        print("Программа будет закрыта...")
        sys.exit(1)
    
    while True:
        show_menu()
        choice = input("Выберите действие (1-6): ").strip()
        
        if choice == "1":
            print("\n➕ ДОБАВЛЕНИЕ НОВОГО ПАРОЛЯ")
            service = input("Название сервиса: ").strip()
            if not service:
                print("❌ Название не может быть пустым!")
                continue
            
            username = input("Имя пользователя: ").strip()
            password = getpass.getpass("Пароль: ")
            if not password:
                print("❌ Пароль не может быть пустым!")
                continue
            
            pm.add_password(service, username, password)
        
        elif choice == "2":
            print("\n🔑 ПОЛУЧЕНИЕ ПАРОЛЯ")
            service = select_service(pm, "получения")
            if service:
                result = pm.get_password(service)
                if result:
                    print("\n" + "="*40)
                    print(f"🔑 {service}")
                    print("="*40)
                    print(f"👤 Логин:    {result['username']}")
                    print(f"🔐 Пароль:   {result['password']}")
                    print("="*40)
            
            input("\nНажмите Enter для продолжения...")
        
        elif choice == "3":
            print("\n📋 СПИСОК СЕРВИСОВ")
            services = pm.list_services()
            if services:
                print(f"\nВсего сохранено: {len(services)}")
                for i, service in enumerate(services, 1):
                    print(f"  {i}. {service}")
            else:
                print("📭 Нет сохраненных паролей!")
            
            input("\nНажмите Enter для продолжения...")
        
        elif choice == "4":
            print("\n🗑️ УДАЛЕНИЕ ПАРОЛЯ")
            service = select_service(pm, "удаления")
            if service:
                confirm = input(f"Вы уверены, что хотите удалить '{service}'? (д/н): ").lower()
                if confirm == 'д':
                    pm.delete_password(service)
                else:
                    print("❌ Удаление отменено")
            
            input("\nНажмите Enter для продолжения...")
        
        elif choice == "5":
            print("\n🔄 СМЕНА МАСТЕР-ПАРОЛЯ")
            print("="*40)
            
            old_pass = getpass.getpass("Введите ТЕКУЩИЙ мастер-пароль: ")
            new_pass = getpass.getpass("Введите НОВЫЙ мастер-пароль: ")
            confirm_pass = getpass.getpass("Повторите новый мастер-пароль: ")
            
            if new_pass != confirm_pass:
                print("❌ Новые пароли не совпадают!")
                input("\nНажмите Enter для продолжения...")
                continue
            
            if pm.change_master_password(old_pass, new_pass):
                print("🔐 Пожалуйста, запомните новый мастер-пароль!")
            
            input("\nНажмите Enter для продолжения...")
        
        elif choice == "6":
            print("\n👋 До свидания!")
            break
        
        else:
            print("❌ Неверная команда! Выберите 1-6")
            input("\nНажмите Enter для продолжения...")

if __name__ == "__main__":
    main()