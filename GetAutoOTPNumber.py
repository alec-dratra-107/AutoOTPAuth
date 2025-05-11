import os
import time
import random
import string
import ctypes
import threading
import psutil
import configparser
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager

is_running = True

def debug_log(message, log_level="INFO"):
    # ctypes.windll.kernel32.OutputDebugStringW(f"[{log_level}] {message}")
    # print(f"[{log_level}] {message}")
    return

def generate_base32_string(length=8):
    base32_chars = string.ascii_uppercase + "234567"
    return ''.join(random.choice(base32_chars) for _ in range(length))

def load_login_credentials(file_path="login.txt"):
    debug_log(f"try to load the login file: {file_path}", "DEBUG")
    try:
        if not os.path.exists(file_path):
            debug_log(f"file not exist: {file_path}", "ERROR")
            return None, None

        email = None
        password = None
        
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("[AccountInfo]"):
                    continue
                elif line.startswith("ID="):
                    email = line.split("ID=")[1].strip()
                elif line.startswith("Password="):
                    password = line.split("Password=")[1].strip()
                
                if email and password:
                    debug_log(f"account to use: {email}", "INFO")
                    return email, password
        
        if not email or not password:
            debug_log("not found valid account", "ERROR")
            return None, None
            
    except Exception as e:
        debug_log(f"failed to load login information: {str(e)}", "ERROR")
        return None, None

def perform_login(driver, email, password):
    try:
        debug_log("looking for the login button...")
        login_button = WebDriverWait(driver, 15).until(
            EC.element_to_be_clickable((By.ID, "loginOrRegister"))
        )
        driver.execute_script("arguments[0].click();", login_button)
        debug_log("finish to click login button")

        time.sleep(1)
        debug_log("iframe converting...")
        WebDriverWait(driver, 15).until(
            EC.frame_to_be_available_and_switch_to_it((By.ID, "layui-layer-iframe1"))
        )
        debug_log("iframe conversion finished")

        time.sleep(1)
        debug_log("looking for the email input field...")
        email_input = WebDriverWait(driver, 15).until(
            EC.visibility_of_element_located((By.ID, "username"))
        )
        email_input.clear()
        email_input.send_keys(email)
        debug_log(f"finish to input email: {email}")

        time.sleep(1)
        debug_log("looking for the password input field...")
        password_input = WebDriverWait(driver, 15).until(
            EC.visibility_of_element_located((By.ID, "password"))
        )
        password_input.clear()
        password_input.send_keys(password)
        debug_log("finish to input password")

        time.sleep(1)
        debug_log("try to click the login button...")
        login_submit = WebDriverWait(driver, 15).until(
            EC.element_to_be_clickable((By.CSS_SELECTOR, "button#login.btn.btn-primary"))
        )
        driver.execute_script("arguments[0].click();", login_submit)
        debug_log("finish to click the login button")

        WebDriverWait(driver, 15).until(
            EC.invisibility_of_element_located((By.CSS_SELECTOR, "div.modal-dialog"))
        )
        debug_log("confirm login success")
        time.sleep(1)
        driver.switch_to.default_content()
        return True

    except Exception as e:
        debug_log(f"[ERROR] error during login process: {e}")
        driver.save_screenshot("login_error.png")
        return False

def get_otp_serial_values(file_path):
    config = configparser.ConfigParser()
    config.read(file_path)
    
    if 'OTPSerial' in config:
        return list(config['OTPSerial'].values())
    else:
        debug_log("[OTPSerial] cannot find section info.")
        return []

def otp_process(driver):
    try:
        while True:
            cards = WebDriverWait(driver, 15).until(
                EC.presence_of_all_elements_located((By.CSS_SELECTOR, "div.latestTool.mr20.toolActive"))
            )

            w_otp_count = len(cards)
            debug_log(f"cards count:{w_otp_count}")
            if w_otp_count > 0:
                w_otp_count -= 1

            title_list = []

            with open("Result.txt", "w", encoding="utf-8") as file:
                file.write("[Result]\n")
                file.write(f"Count={w_otp_count}\n")

                result = []
                i = 0
                for i in range(w_otp_count):
                    try:
                        card = cards[i]
                        debug_log(f"title extraction")
                        title_element = card.find_element(By.CSS_SELECTOR, "p[name='title']")

                        title = title_element.text.strip()
                        title_list.append(title)
                        debug_log(f"title result:{title}")

                        debug_log(f"dynamicPassword extraction")
                        otp_element = card.find_element(By.CSS_SELECTOR, "div.detailIntro[name='dynamicPassword']")

                        otp_code = otp_element.text.strip()
                        debug_log(f"password result:{otp_code}")
                        
                        file.write(f"{title}={otp_code}\n")

                    except Exception as e:
                        debug_log(f"error found in extracting an important info in card: {e}")
                        continue

            file_path = 'OTPSerial.txt'

            f_otp_serials = get_otp_serial_values(file_path)
            for serial in f_otp_serials:
                debug_log(f"serial={serial}")
                already_exist_serial = False
                for title in title_list:
                    debug_log(f"title={title}")
                    if serial == title:
                        already_exist_serial = True
                        break

                if already_exist_serial == True:
                    continue
                
                debug_log(f"+BUTTON finding...")
                butAddDynamicPassword = WebDriverWait(driver, 15).until(
                    EC.element_to_be_clickable((By.ID, "butAddDynamicPassword"))
                )

                time.sleep(1)

                if butAddDynamicPassword.is_displayed():
                    debug_log("+ BUTTON not appeared in the screen.")
                    
                    driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", butAddDynamicPassword)
                    time.sleep(0.5)
                    
                    driver.execute_script("arguments[0].click();", butAddDynamicPassword)
                    debug_log("+BUTTON click success")
                else:
                    debug_log("element not appeared in the screen.")

                debug_log(f"waiting for the dialog window")
                add_popup = WebDriverWait(driver, 15).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, ".layui-layer-dialog"))
                )

                debug_log(f"input title={serial}")
                title_input = driver.find_element(By.ID, "addDynamicPasswordTitle")
                title_input.clear()
                title_input.send_keys(serial)

                time.sleep(0.5)

                debug_log(f"input password={serial}")
                password_input = driver.find_element(By.ID, "addDynamicPasswordPassword")
                password_input.clear()
                password_input.send_keys(serial) 

                time.sleep(0.5)

                debug_log(f"click ADD button")
                add_button = driver.find_element(By.CSS_SELECTOR, ".layui-layer-btn0")
                add_button.click()

                time.sleep(1)

            time.sleep(2)
            debug_log(f"Addition finished")

    except Exception as e:
        debug_log(f"error found in finding OTP card: {e}")

def login_to_lzltool(driver):
    email, password = load_login_credentials()
    if not email or not password:
        debug_log("no usable login info.", "ERROR")
        return False

    driver.get("https://lzltool.com/GoogleDynamicPassword")
    time.sleep(1)

    debug_log(f"try to login: {email}", "INFO")
    if perform_login(driver, email, password):
        otp_process(driver)
        return True
    return False

def get_chrome_driver_pid(driver):
    try:
        return driver.service.process.pid
    except AttributeError:
        current_pid = os.getpid()
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if 'chrome' in proc.info['name'].lower():
                    if proc.info['cmdline'] and any('--test-type=webdriver' in cmd for cmd in proc.info['cmdline']):
                        return proc.info['pid']
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return None

def get_browser_pid(driver):
    driver_pid = driver.service.process.pid
    driver_process = psutil.Process(driver_pid)
    
    children = driver_process.children(recursive=True)
    pids = [child.pid for child in children]
    
    debug_log("all children process info:")
    for i, pid in enumerate(pids, 1):
        debug_log(f"[{i}] PID: {pid}")
    
    return pids

def is_process_running(process_name):
    for proc in psutil.process_iter(['name']):
        if proc.info['name'] == process_name:
            return True
    return False
def main():
    global is_running
    chrome_options = Options()
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--window-size=1920,1080")
    # chrome_options.add_argument("--headless=new")  # Chrome 109 이상 버전에서는 --headless=new 권장
    
    try:
        debug_log(f"START", "INFO")
        driver = webdriver.Chrome(
            service=Service(ChromeDriverManager().install()),
            options=chrome_options
        )

        chrome_driver_pid = get_chrome_driver_pid(driver)
        debug_log(f"[CHROME] chrome driver pid: {chrome_driver_pid}")
        with open("chromedriver.txt", "w", encoding="utf-8") as f:
            f.write(str(chrome_driver_pid))

        chrome_pids = get_browser_pid(driver)
        debug_log(f"[CHROME] chrome browser PID list: {chrome_pids}")
        chrome_count = len(chrome_pids)
        with open("chrome.txt", "w", encoding="utf-8") as f:
            f.write("[Chrome]\n")
            f.write(f"Count={chrome_count}\n")
            for i, pid in enumerate(chrome_pids, 1):
                f.write(f"PID_{i}={pid}\n")

        if not login_to_lzltool(driver):
            debug_log("work suspended because of login failure")
            return

        while is_running:
            time.sleep(1)

    except Exception as e:
        debug_log(f"[MAIN ERROR] ERROR found in executing main function: {e}")
    finally:
        is_running = False
        if 'driver' in locals():
            driver.quit()

if __name__ == "__main__":
    main()