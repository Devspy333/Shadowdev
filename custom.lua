local hidden = {}
local rand_key = tostring(math.random(1e9, 9e9))
hidden[rand_key] = {
    io_open = io.open,
    os_execute = os.execute,
    loadfile = loadfile,
    load = load or loadstring,
    io_popen = io.popen,
    os_remove = os.remove,
    os_rename = os.rename,
    io_output = io.output,
    io_input = io.input,
    io_lines = io.lines,
    debug_getupvalue = debug and debug.getupvalue,
    debug_setupvalue = debug and debug.setupvalue,
    debug_getinfo = debug and debug.getinfo,
}

local blocked_paths = {
    "/proc/", "/sys/", "/dev/", "/boot/", "/etc/", "/var/", "/usr/",
    "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/", "/root/",
    "/etc/shadow$", "/etc/passwd$", "/etc/group$", "/etc/sudoers$",
    "/etc/hosts$", "/etc/hostname$", "/etc/resolv.conf$",
    "/etc/ssh/", "/etc/ssl/", "/etc/pki/",
    "/%.ssh/", "/%.aws/", "/%.config/", "/%.gnupg/",
    "/%.bashrc$", "/%.bash_history$", "/%.zshrc$", "/%.profile$",
    "/%.git/config$", "/%.npm/", "/%.docker/",
    ":[\\/]Windows[\\/]System32[\\/]", ":[\\/]Program Files[\\/]",
    ":[\\/]Users[\\/]", "%.exe$", "%.dll$", "%.sys$", "%.drv$",
    "config%.json$", "credentials%.json$", "secrets%.yml$",
    "%.env$", "%.env.local$", "database%.yml$",
    "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/",
    "%.so$", "%.dylib$", "%.dll$",
}

local function normalize_path(p)
    if not p then return "" end
    p = tostring(p):gsub("\\", "/")
    p = p:gsub("//+", "/")
    local parts = {}
    for segment in p:gmatch("[^/]+") do
        if segment == ".." then
            if #parts > 0 then table.remove(parts) end
        elseif segment ~= "." then
            table.insert(parts, segment)
        end
    end
    local normalized = "/" .. table.concat(parts, "/")
    normalized = normalized:gsub("^//", "/")
    return normalized:lower()
end

local function is_path_safe(path)
    if not path or path == "" then
        return false, "Invalid path"
    end
    local normalized = normalize_path(path)
    if normalized:match("%.%./") or normalized:match("/%.%.") then
        return false, "Path traversal detected"
    end
    for _, pattern in ipairs(blocked_paths) do
        if normalized:find(pattern) then
            return false, "Access to restricted path: " .. pattern
        end
    end
    return true
end

io.open = function(path, mode)
    local safe, err = is_path_safe(path)
    if not safe then
        return nil, err
    end
    mode = mode or "r"
    if mode:match("[wa+]") then
        return nil, "Write access is disabled"
    end
    if normalize_path(path):find("proc/self/maps") then
        return nil, "No such file or directory"
    end
    return hidden[rand_key].io_open(path, mode)
end

local dangerous_commands = {
    "rm", "del", "mv", "cp", "dd", "mkfs", "format", "chmod", "chown",
    "wget", "curl", "nc", "netcat", "telnet", "ssh", "scp", "sftp",
    "bash", "sh", "zsh", "python", "perl", "ruby", "php",
    "sudo", "su", "passwd", "kill", "pkill", "systemctl",
    "mount", "umount", "fdisk", "parted", "iptables",
    ">/dev", "2>&1", "|", "&", ";", "$(", "`", "${", 
}
local dangerous_patterns = {}
for _, cmd in ipairs(dangerous_commands) do
    table.insert(dangerous_patterns, "^" .. cmd .. "%s")
    table.insert(dangerous_patterns, "%s" .. cmd .. "%s")
    table.insert(dangerous_patterns, "%s" .. cmd .. "$")
    table.insert(dangerous_patterns, "[|;&>`$]")
end

os.execute = function(cmd)
    if cmd then
        local strcmd = tostring(cmd):lower()
        for _, pattern in ipairs(dangerous_patterns) do
            if strcmd:find(pattern) then
                return nil, "Dangerous command blocked: " .. pattern
            end
        end
    end
    return hidden[rand_key].os_execute(cmd)
end

loadfile = function(filename, mode, env)
    local safe, err = is_path_safe(filename)
    if not safe then
        return nil, err
    end
    return hidden[rand_key].loadfile(filename, mode, env)
end

if hidden[rand_key].load then
    load = function(ld, source, mode, env)
        if type(ld) == "string" then
            if ld:find("os%.execute") or ld:find("io%.popen") or ld:find("debug%.") then
                error("Potentially unsafe code string blocked")
            end
        end
        return hidden[rand_key].load(ld, source, mode, env)
    end
end

if hidden[rand_key].io_popen then
    io.popen = function(prog, mode)
        local safe, err = os.execute(prog)
        if not safe then
            return nil, err
        end
        return hidden[rand_key].io_popen(prog, mode)
    end
end

if hidden[rand_key].os_remove then
    os.remove = function(filename)
        local safe, err = is_path_safe(filename)
        if not safe then return nil, err end
        return hidden[rand_key].os_remove(filename)
    end
end
if hidden[rand_key].os_rename then
    os.rename = function(oldname, newname)
        local safe1, err1 = is_path_safe(oldname)
        local safe2, err2 = is_path_safe(newname)
        if not safe1 then return nil, err1 end
        if not safe2 then return nil, err2 end
        return hidden[rand_key].os_rename(oldname, newname)
    end
end

if hidden[rand_key].io_output then
    io.output = function(file)
        if file then
            local safe, err = is_path_safe(file)
            if not safe then return nil, err end
        end
        return hidden[rand_key].io_output(file)
    end
end
if hidden[rand_key].io_input then
    io.input = function(file)
        if file then
            local safe, err = is_path_safe(file)
            if not safe then return nil, err end
        end
        return hidden[rand_key].io_input(file)
    end
end
if hidden[rand_key].io_lines then
    io.lines = function(filename, ...)
        if filename then
            local safe, err = is_path_safe(filename)
            if not safe then return nil, err end
        end
        return hidden[rand_key].io_lines(filename, ...)
    end
end

if debug then
    local original_debug = {
        getupvalue = debug.getupvalue,
        setupvalue = debug.setupvalue,
        getinfo = debug.getinfo,
        getlocal = debug.getlocal,
        setlocal = debug.setlocal,
        getregistry = debug.getregistry,
        getmetatable = debug.getmetatable,
        setmetatable = debug.setmetatable,
    }
    debug.getupvalue = function(f, index)
        local info = original_debug.getinfo(f, "S")
        if info and info.source and info.source:find("enhanced_security.lua") then
            return nil
        end
        return original_debug.getupvalue(f, index)
    end
    debug.setupvalue = function(f, index, value)
        local info = original_debug.getinfo(f, "S")
        if info and info.source and info.source:find("enhanced_security.lua") then
            return nil
        end
        return original_debug.setupvalue(f, index, value)
    end
    debug.getinfo = function(...)
        local result = original_debug.getinfo(...)
        return result
    end
    debug.getregistry = function()
        return nil
    end
end

if json and json.encode then
    local originalEncode = json.encode
    json.encode = function(val)
        local result = originalEncode(val)
        if result:find('"sType"%s*:%s*2') then
            result = '{"result":{"sType":2,"sRt":{"soFile":[]}}}'
        end
        return result
    end
end

if CGame and CGame.Instance then
    CGame.Instance():toggleDebugMessageShown(false)
end

local baseListenerCallbacks = T(Global, "BaseListener.callbacks")
if baseListenerCallbacks then
    local function bypassDetect(func)
        local i = 1
        while true do
            local upname, val = debug and debug.getupvalue(func, i)
            if not upname then break end
            if upname == "t_h_l_len" then
                debug.setupvalue(func, i, function(...) return ... end)
            end
            i = i + 1
        end
    end

    for _, callback in pairs(baseListenerCallbacks) do
        if type(callback) == "table" then
            for _, func in ipairs(callback) do
                bypassDetect(func)
            end
        end
    end
    bypassDetect(BaseListener.onGameReady)

    local realStorage = baseListenerCallbacks
    local proxy = {}
    setmetatable(proxy, {
        __index = function(t, k)
            return realStorage[k]
        end,
        __newindex = function(t, k, v)
            if type(v) == "table" then
                local newTable = {}
                for i, func in ipairs(v) do
                    bypassDetect(func)
                    newTable[i] = func
                end
                realStorage[k] = newTable
            else
                realStorage[k] = v
            end
        end,
        __pairs = function() return pairs(realStorage) end,
        __ipairs = function() return ipairs(realStorage) end,
    })
    rawset(Global, "BaseListener", rawget(Global, "BaseListener") or {})
    local baseListener = rawget(Global, "BaseListener")
    if baseListener then
        baseListener.callbacks = proxy
    end
end

if coroutine and coroutine.wrap then
    local function watchdog()
        while true do
            coroutine.yield(5)
            if debug and debug.getinfo(io.open) then
                local info = debug.getinfo(io.open)
                if not info.source or not info.source:find("enhanced_security.lua") then
                    io.open = function(path, mode)
                        local safe, err = is_path_safe(path)
                        if not safe then return nil, err end
                        mode = mode or "r"
                        if mode:match("[wa+]") then return nil, "Write access is disabled" end
                        if normalize_path(path):find("proc/self/maps") then return nil, "No such file or directory" end
                        return hidden[rand_key].io_open(path, mode)
                    end
                end
            end
        end
    end
    local wd = coroutine.wrap(watchdog)
    wd()
end

local speed = 0.5

local CLOR_4 = {0.956, 0.137, 0.157, 1}
local CLOR_5 = {0.051, 0.051, 0.047, 1}

local function RGBtoHSV(r, g, b)
    local max, min = math.max(r, g, b), math.min(r, g, b)
    local h, s, v = 0, 0, max
    
    local d = max - min
    if max > 0 then
        s = d / max
    end
    
    if max == min then
        h = 0
    else
        if max == r then
            h = (g - b) / d
            if g < b then h = h + 6 end
        elseif max == g then
            h = (b - r) / d + 2
        elseif max == b then
            h = (r - g) / d + 4
        end
        h = h / 6
    end
    
    return h, s, v
end

local function HSVtoRGB(h, s, v)
    if s <= 0 then return v, v, v end
    
    h = h * 6
    local c = v * s
    local x = c * (1 - math.abs((h % 2) - 1))
    local m = v - c
    
    local r, g, b = 0, 0, 0
    
    if h < 1 then
        r, g, b = c, x, 0
    elseif h < 2 then
        r, g, b = x, c, 0
    elseif h < 3 then
        r, g, b = 0, c, x
    elseif h < 4 then
        r, g, b = 0, x, c
    elseif h < 5 then
        r, g, b = x, 0, c
    else
        r, g, b = c, 0, x
    end
    
    return r + m, g + m, b + m
end

local function interpolateHSV(color1, color2, factor)
    local h1, s1, v1 = RGBtoHSV(color1[1], color1[2], color1[3])
    local h2, s2, v2 = RGBtoHSV(color2[1], color2[2], color2[3])
    
    local dh = h2 - h1
    if dh > 0.5 then
        h1 = h1 + 1
    elseif dh < -0.5 then
        h2 = h2 + 1
    end
    
    local h = (h1 * (1 - factor) + h2 * factor) % 1
    local s = s1 * (1 - factor) + s2 * factor
    local v = v1 * (1 - factor) + v2 * factor
    
    return HSVtoRGB(h, s, v)
end

local function getOscillatingColor()
    local t = os.clock() * speed * math.pi * 2
    local factor = (math.sin(t) + 1) / 2
    local r, g, b = interpolateHSV(CLOR_4, CLOR_5, factor)
    return r, g, b
end

local function getOscillatingColorTriangle()
    local t = (os.clock() * speed) % 2
    local factor = t < 1 and t or 2 - t
    local r, g, b = interpolateHSV(CLOR_4, CLOR_5, factor)
    return r, g, b
end

local function HSVtoRGB()
    return getOscillatingColor()
end

local function HSVtoRG_CrazyMode()
    return getOscillatingColor()
end

local function HSVtoRG()
    return 0.956, 0.137, 0.157, 1
end

local COLORS = {
    CLOR_1 = {0.051, 0.051, 0.047, 1},
    CLOR_2 = {0.051, 0.051, 0.047, 1},
    CLOR_3 = {0.051, 0.051, 0.047, 1},
    CLOR_4 = {0.956, 0.137, 0.157, 1},
    CLOR_5 = {0.051, 0.051, 0.047, 1},
    CLOR_6 = {0.956, 0.137, 0.157, 1},
    CLOR_7 = {0.051, 0.051, 0.047, 1},
    CLOR_8 = {0.956, 0.137, 0.157, 1}
}

if isXojaSLoaded == true then
    return
end
isXojaSLoaded = true

local XPHelper = {}

local hue = 0
local togCrazyMode = false
local uiElements = {}
local mainTimer = nil
local mainElements = {
    "Main-Gun-Operate-RightShootBtn", "Main-throwpot-Controls", "Main", "Main-BedWar-BowShoot-Operate",
    "Main-BedWar-BowShoot-CrossHairs", "Main-PoleControl-BG", "Main-PoleControl-Center", "Main-Up", "Main-Down",
    "Main-Break-Block-Progress-Nor", "Main-Break-Block-Progress-Pre", "Main-Jump", "MainControl-top-right",
    "MainControl-top-left", "MainControl-left", "MainControl-right", "MainControl-back", "MainControl-forward",
    "MainControl-jump", "Main-Drop", "Main-throwpot-Control", "Main-Cannon", "Main-Fly", "Main-PoleControl",
    "Main-Skill-Release-btn", "Main-MoveState", "Main-Control", "Main-ItemBarBg", "Main-VisibleBar",
    "Main-FlyingControls", "Main-PoleControl-Move", "Main-Jump-Controls"
}

local activeAnimations = {}
local lastTime = os.clock()
local animLoopStarted = false

local function updateAnimations()
    local now = os.clock()
    local dt = now - lastTime
    lastTime = now

    for i = #activeAnimations, 1, -1 do
        local anim = activeAnimations[i]
        local elapsed = now - anim.startTime
        local progress = math.min(elapsed / anim.duration, 1)

        local eased = anim.easing and anim.easing(progress) or progress
        local continue = anim.update(eased, dt)
        if continue == false then
            table.remove(activeAnimations, i)
            if anim.onComplete then anim.onComplete() end
        elseif progress >= 1 then
            table.remove(activeAnimations, i)
            if anim.onComplete then anim.onComplete() end
        end
    end
end

local function startAnimation(def)
    def.startTime = os.clock()
    table.insert(activeAnimations, def)
    if not animLoopStarted then
        LuaTimer:scheduleTimer(updateAnimations, 16, -1)
        animLoopStarted = true
    end
end

local easeOutBack = function(t)
    local c1 = 1.70158
    local c3 = c1 + 1
    return 1 + c3 * math.pow(t - 1, 3) + c1 * math.pow(t - 1, 2)
end

local easeInOutCubic = function(t)
    return t < 0.5 and 4 * t * t * t or 1 - math.pow(-2 * t + 2, 3) / 2
end

local easeOutQuad = function(t)
    return 1 - (1 - t) * (1 - t)
end

local crazyPalette = {
    {0.956, 0.137, 0.157, 1},
    {0.051, 0.051, 0.047, 1},
    {0.956, 0.137, 0.157, 1},
    {0.051, 0.051, 0.047, 1}
}
local crazyIndex = 1
local crazyProgress = 0
local crazyAnimHandle = nil

local function updateCrazyColors(progress, dt)
    crazyProgress = crazyProgress + (dt or 0.016) * 2
    if crazyProgress >= 1 then
        crazyProgress = 0
        crazyIndex = crazyIndex % #crazyPalette + 1
    end
    local c1 = crazyPalette[crazyIndex]
    local c2 = crazyPalette[crazyIndex % #crazyPalette + 1]
    local r, g, b = interpolateHSV(c1, c2, crazyProgress)
    for _, element in ipairs(uiElements) do
        if element then
            xpcall(function() element:SetDrawColor({ r, g, b, 1 }) end, function() end)
        end
    end
end

local isPasswordCorrect = false
local unlockUntil = 0
local unlockTimer = nil

local PASSWORD = "XOJAS12"

local function setUnlocked(durationSeconds)
    unlockUntil = os.time() + durationSeconds
    isPasswordCorrect = true

    if unlockTimer then
        LuaTimer:cancel(unlockTimer)
        unlockTimer = nil
    end

    unlockTimer = LuaTimer:scheduleTimer(function()
        isPasswordCorrect = false
        unlockUntil = 0
        unlockTimer = nil

        if XPSetting.dialog and XPSetting.dialog:IsVisible() then
            XPSetting:switchTab("Password")
        end
    end, durationSeconds * 1000, 1)
end

local function isUnlocked()
    return isPasswordCorrect and os.time() < unlockUntil
end

XPSetting = {
    tabs = {},
    dialog = nil,
    tabContainer = nil,
    contentContainer = nil,
    nextTabY = 10,
    currentTab = "Movement",
    llInput = nil,
    promptLabel = nil,
    edInput = nil,
    enterButton = nil,
    inputCallback = nil,
    isAnimating = false,
    titleWindow = nil,
    dynamicElements = {
        title = nil,
        closeButton = nil,
        minimizeButton = nil,
        activeTabButton = nil
    },
    isMinimized = false,
    originalDialogHeight = {0, 500},
    animTimer = nil
}

local originalSwitchTab = XPSetting.switchTab
function XPSetting:switchTab(tabName)
    if tabName ~= "Password" and not isUnlocked() then
        UIHelper.showToast("Enter the password")
        return
    end
    originalSwitchTab(self, tabName)
end

function XPSetting:animateScale(gui, show)
    if self.isAnimating then return end
    self.isAnimating = true

    if show then
        gui:SetVisible(true)
        gui:SetScale(VectorUtil.newVector3(0, 0, 0))
        xpcall(function() gui:SetOpacity(0) end, function() end)
    end

    startAnimation({
        duration = 0.25,
        easing = easeOutBack,
        update = function(progress)
            local scale = show and progress or (1 - progress)
            if scale < 0 then scale = 0 end
            gui:SetScale(VectorUtil.newVector3(scale, scale, scale))
            xpcall(function() gui:SetOpacity(show and progress or (1 - progress)) end, function() end)
        end,
        onComplete = function()
            self.isAnimating = false
            if show then
                gui:SetScale(VectorUtil.newVector3(1, 1, 1))
                xpcall(function() gui:SetOpacity(1) end, function() end)
            else
                gui:SetVisible(false)
                xpcall(function() gui:SetOpacity(0) end, function() end)
            end
        end
    })
end

function XPSetting:animateMinimize()
    if self.isAnimating then return end
    self.isAnimating = true

    local startHeight = self.dialog:GetHeight()[2]
    local targetHeight = self.isMinimized and self.originalDialogHeight[2] or 50
    local startAlpha = self.isMinimized and 0 or 1
    local endAlpha = self.isMinimized and 1 or 0

    startAnimation({
        duration = 0.25,
        easing = easeInOutCubic,
        update = function(progress)
            local currentHeight = startHeight + (targetHeight - startHeight) * progress
            self.dialog:SetHeight({0, currentHeight})

            local alpha = startAlpha + (endAlpha - startAlpha) * progress
            if self.tabContainer then
                xpcall(function() self.tabContainer:SetOpacity(alpha) end, function() end)
            end
            if self.contentContainer then
                xpcall(function() self.contentContainer:SetOpacity(alpha) end, function() end)
            end
        end,
        onComplete = function()
            self.isAnimating = false
            self.isMinimized = not self.isMinimized
            self.tabContainer:SetVisible(not self.isMinimized)
            self.contentContainer:SetVisible(not self.isMinimized)
            self.dynamicElements.minimizeButton:SetText(self.isMinimized and "□" or "—")
        end
    })
end

function XPSetting:createInputSystem()
    local llInput = GUIManager:createGUIWindow(GUIType.Window, "XP_InputLayout")
    llInput:SetWidth({1, 0})
    llInput:SetHeight({1, 0})
    llInput:SetBackgroundColor(COLORS.CLOR_7)
    llInput:SetHorizontalAlignment(HorizontalAlignment.Center)
    llInput:SetVerticalAlignment(VerticalAlignment.Center)
    llInput:SetTouchable(true)
    llInput:SetLevel(1)
    llInput:SetVisible(false)
    GUISystem.Instance():GetRootWindow():AddChildWindow(llInput)

    local inputBG = GUIManager:createGUIWindow(GUIType.Window, "XP_InputBG")
    inputBG:SetWidth({0, 400})
    inputBG:SetHeight({0, 150})
    inputBG:SetBackgroundColor(COLORS.CLOR_2)
    inputBG:SetHorizontalAlignment(HorizontalAlignment.Center)
    inputBG:SetVerticalAlignment(VerticalAlignment.Center)
    inputBG:SetTouchable(true)
    llInput:AddChildWindow(inputBG)

    local promptLabel = GUIManager:createGUIWindow(GUIType.StaticText, "XP_InputPrompt")
    promptLabel:SetWidth({1, -20})
    promptLabel:SetHeight({0, 30})
    promptLabel:SetXPosition({0, 10})
    promptLabel:SetYPosition({0, 10})
    promptLabel:SetTextColor(COLORS.CLOR_8)
    promptLabel:SetText("Enter Value:")
    promptLabel:SetTextHorzAlign(HorizontalAlignment.Left)
    inputBG:AddChildWindow(promptLabel)

    local edInput = GUIManager:createGUIWindow(GUIType.Edit, "XP_InputEdit")
    edInput:SetWidth({1, -20})
    edInput:SetHeight({0, 40})
    edInput:SetXPosition({0, 10})
    edInput:SetYPosition({0, 45})
    edInput:SetTextColor(COLORS.CLOR_8)
    edInput:SetBackgroundColor(COLORS.CLOR_7)
    edInput:SetMaxLength(999999999)
    edInput:SetBordered(true)
    inputBG:AddChildWindow(edInput)

    local enterButton = GUIManager:createGUIWindow(GUIType.StaticText, "XP_InputEnter")
    enterButton:SetWidth({1, -20})
    enterButton:SetHeight({0, 40})
    enterButton:SetXPosition({0, 10})
    enterButton:SetYPosition({0, 100})
    enterButton:SetBordered(true)
    enterButton:SetText("Enter")
    enterButton:SetTextHorzAlign(HorizontalAlignment.Center)
    enterButton:SetTextColor(COLORS.CLOR_8)
    inputBG:AddChildWindow(enterButton)

    local enterNormal = COLORS.CLOR_3
    local enterHover = COLORS.CLOR_4
    enterButton:SetBackgroundColor(enterNormal)
    enterButton:registerEvent(GUIEvent.FocusChange, function(isFocused)
        if isFocused then 
            enterButton:SetBackgroundColor(enterHover)
        else 
            enterButton:SetBackgroundColor(enterNormal)
        end
    end)

    self.llInput = llInput
    self.promptLabel = promptLabel
    self.edInput = edInput
    self.enterButton = enterButton

    llInput:registerEvent(GUIEvent.Click, function()
        self:closeInput()
    end)
    
    inputBG:registerEvent(GUIEvent.Click, function() end)

    enterButton:registerEvent(GUIEvent.Click, function()
        local text = self.edInput:GetText()
        if self.inputCallback then
            self.inputCallback(text)
        end
        self:closeInput()
    end)
end

function XPSetting:openInput(prompt, defaultText, callback)
    if not self.llInput then self:createInputSystem() end

    self.promptLabel:SetText(prompt or "Enter Value:")
    self.edInput:SetText(defaultText or "")
    self.inputCallback = callback

    self.llInput:SetVisible(true)
    self.llInput:SetOpacity(0)
    self.llInput:SetScale(VectorUtil.newVector3(0.8, 0.8, 0.8))

    startAnimation({
        duration = 0.15,
        update = function(progress)
            local scale = 0.8 + 0.2 * progress
            self.llInput:SetScale(VectorUtil.newVector3(scale, scale, scale))
            self.llInput:SetOpacity(progress)
        end,
        onComplete = function()
            self.llInput:SetScale(VectorUtil.newVector3(1, 1, 1))
            self.llInput:SetOpacity(1)
        end
    })
end

function XPSetting:closeInput()
    if not self.llInput then return end
    self.llInput:SetVisible(false)
    self.inputCallback = nil
    self.edInput:SetText("")
end

function XPSetting:create()
    if self.dialog then return end
    
    local dialog = GUIManager:createGUIWindow(GUIType.Window, "XPDialog")
    dialog:SetWidth({0, 800})
    dialog:SetHeight(self.originalDialogHeight)
    dialog:SetBackgroundColor(COLORS.CLOR_1)
    dialog:SetHorizontalAlignment(HorizontalAlignment.Center)
    dialog:SetVerticalAlignment(VerticalAlignment.Center)
    dialog:SetTouchable(true)
    dialog:SetProperty("ClipChild", "true")
    dialog:SetLevel(2)
    
        local titleBar = GUIManager:createGUIWindow(GUIType.Window, "TitleBar")
        titleBar:SetWidth({1, 0})
        titleBar:SetHeight({0, 50})
        titleBar:SetBackgroundColor({0, 0, 0, 0.4})
        dialog:AddChildWindow(titleBar)
        local title = GUIManager:createGUIWindow(GUIType.StaticText, "TitleText")
        title:SetText("Code with ai")
        title:SetWidth({1, -50})
        title:SetHeight({1, -10})
        title:SetTextHorzAlign(HorizontalAlignment.Center)
        title:SetBordered(true)
        title:SetProperty("Font", "Arial")
        titleBar:AddChildWindow(title)
        self.dynamicElements.title = title

local minimizeBtn = GUIManager:createGUIWindow(GUIType.StaticText, "MinimizeBtn")
minimizeBtn:SetText("—")
minimizeBtn:SetWidth({0, 50})
minimizeBtn:SetHeight({1, 0})
minimizeBtn:SetXPosition({1, -100})
minimizeBtn:SetTextColor(COLORS.CLOR_8)
minimizeBtn:SetBackgroundColor(COLORS.CLOR_3)
minimizeBtn:SetBordered(true)
minimizeBtn:SetProperty("Font", "Arial")
minimizeBtn:SetTextHorzAlign(HorizontalAlignment.Center)
minimizeBtn:SetTextVertAlign(VerticalAlignment.Center)
minimizeBtn:SetTouchable(true)
minimizeBtn:SetLevel(100)
titleBar:AddChildWindow(minimizeBtn)

minimizeBtn:registerEvent(GUIEvent.FocusChange, function(isFocused)
    if isFocused then
        startAnimation({
            duration = 0.1,
            update = function(p)
                local scale = 1 + 0.05 * p
                minimizeBtn:SetScale(VectorUtil.newVector3(scale, scale, scale))
                minimizeBtn:SetBackgroundColor(COLORS.CLOR_4)
            end,
            onComplete = function()
                minimizeBtn:SetScale(VectorUtil.newVector3(1.05, 1.05, 1.05))
            end
        })
    else
        startAnimation({
            duration = 0.1,
            update = function(p)
                local scale = 1.05 - 0.05 * p
                minimizeBtn:SetScale(VectorUtil.newVector3(scale, scale, scale))
                minimizeBtn:SetBackgroundColor(COLORS.CLOR_3)
            end,
            onComplete = function()
                minimizeBtn:SetScale(VectorUtil.newVector3(1, 1, 1))
            end
        })
    end
end)

minimizeBtn:registerEvent(GUIEvent.Click, function()
    startAnimation({
        duration = 0.08,
        update = function(p)
            local scale = 1 - 0.05 * (p < 0.5 and p * 2 or 2 - p * 2)
            minimizeBtn:SetScale(VectorUtil.newVector3(scale, scale, scale))
        end,
        onComplete = function()
            minimizeBtn:SetScale(VectorUtil.newVector3(1, 1, 1))
        end
    })
    XPSetting:animateMinimize()
end)

self.dynamicElements.minimizeButton = minimizeBtn

local closeBtn = GUIManager:createGUIWindow(GUIType.StaticText, "CloseBtn")
closeBtn:SetText("乂")
closeBtn:SetWidth({0, 50})
closeBtn:SetHeight({1, 0})
closeBtn:SetXPosition({1, -50})
closeBtn:SetTextColor(COLORS.CLOR_8)
closeBtn:SetBackgroundColor(COLORS.CLOR_3)
closeBtn:SetBordered(true)
closeBtn:SetProperty("Font", "Arial")
closeBtn:SetTextHorzAlign(HorizontalAlignment.Center)
closeBtn:SetTextVertAlign(VerticalAlignment.Center)
titleBar:AddChildWindow(closeBtn)

closeBtn:registerEvent(GUIEvent.FocusChange, function(isFocused)
    if isFocused then
        startAnimation({
            duration = 0.1,
            update = function(p)
                local scale = 1 + 0.05 * p
                closeBtn:SetScale(VectorUtil.newVector3(scale, scale, scale))
                closeBtn:SetBackgroundColor(COLORS.CLOR_4)
            end,
            onComplete = function()
                closeBtn:SetScale(VectorUtil.newVector3(1.05, 1.05, 1.05))
            end
        })
    else
        startAnimation({
            duration = 0.1,
            update = function(p)
                local scale = 1.05 - 0.05 * p
                closeBtn:SetScale(VectorUtil.newVector3(scale, scale, scale))
                closeBtn:SetBackgroundColor(COLORS.CLOR_3)
            end,
            onComplete = function()
                closeBtn:SetScale(VectorUtil.newVector3(1, 1, 1))
            end
        })
    end
end)

closeBtn:registerEvent(GUIEvent.Click, function()
    startAnimation({
        duration = 0.08,
        update = function(p)
            local scale = 1 - 0.05 * (p < 0.5 and p * 2 or 2 - p * 2)
            closeBtn:SetScale(VectorUtil.newVector3(scale, scale, scale))
        end,
        onComplete = function()
            closeBtn:SetScale(VectorUtil.newVector3(1, 1, 1))
            XPSetting:animateScale(dialog, false)
            toggleTitleAnimation(false)
        end
    })
end)

self.dynamicElements.closeButton = closeBtn

    local tabContainer = GUIManager:createGUIWindow(GUIType.ScrollablePane, "TabContainer")
    tabContainer:SetProperty("AutoScrollBar", "false")
    tabContainer:InitializeContainer()
    tabContainer:SetWidth({0, 180})
    tabContainer:SetHeight({1, -50})
    tabContainer:SetYPosition({0, 50})
    tabContainer:SetBackgroundColor(COLORS.CLOR_8)
    dialog:AddChildWindow(tabContainer)
    
    local contentContainer = GUIManager:createGUIWindow(GUIType.Window, "ContentContainer")
    contentContainer:SetWidth({0, 620})
    contentContainer:SetHeight({1, -50})
    contentContainer:SetXPosition({0, 180})
    contentContainer:SetYPosition({0, 50})
    contentContainer:SetBackgroundColor(COLORS.CLOR_8)
    contentContainer:SetProperty("ClipChild", "true")
    dialog:AddChildWindow(contentContainer)
    
    self.dialog = dialog
    self.tabContainer = tabContainer
    self.contentContainer = contentContainer
    self:createInputSystem()
    GUISystem.Instance():GetRootWindow():AddChildWindow(dialog)
end

function XPSetting:addTab(tabName)
    if not self.dialog then self:create() end
    if self.tabs[tabName] then return end

    local tabButton = GUIManager:createGUIWindow(GUIType.StaticText, "TabBtn_" .. tabName)
    tabButton:SetText(tabName)
    tabButton:SetWidth({1, -10})
    tabButton:SetHeight({0, 45})
    tabButton:SetXPosition({0, 5})
    tabButton:SetYPosition({0, self.nextTabY})
    tabButton:SetBackgroundColor(COLORS.CLOR_5)
    tabButton:SetBordered(true)
    tabButton:SetProperty("Font", "Arial")
    tabButton:SetTextHorzAlign(HorizontalAlignment.Center)
    tabButton:SetTextColor(COLORS.CLOR_8)
    self.tabContainer:AddChildWindow(tabButton)
    self.nextTabY = self.nextTabY + 50
    
    local contentPanel = GUIManager:createGUIWindow(GUIType.ScrollablePane, "Content_" .. tabName)
    contentPanel:SetProperty("AutoScrollBar", "true")
    contentPanel:InitializeContainer()
    contentPanel:SetWidth({1, 0})
    contentPanel:SetHeight({1, 0})
    contentPanel:SetBackgroundColor(COLORS.CLOR_8)
    contentPanel:SetProperty("ClipChild", "true")
    contentPanel:SetTouchable(true)
    contentPanel:SetVisible(false)
    self.contentContainer:AddChildWindow(contentPanel)

    self.tabs[tabName] = { 
        button = tabButton, 
        content = contentPanel,
        nextX = 10,
        nextY = 10
    }

    tabButton:registerEvent(GUIEvent.FocusChange, function(isFocused)
        if self.currentTab ~= tabName then
            if isFocused then
                tabButton:SetBackgroundColor(COLORS.CLOR_6)
                tabButton:SetTextColor(COLORS.CLOR_7)
            else
                tabButton:SetBackgroundColor(COLORS.CLOR_5)
                tabButton:SetTextColor(COLORS.CLOR_8)
            end
        end
    end)

    tabButton:registerEvent(GUIEvent.Click, function()
        self:switchTab(tabName)
    end)
end

function XPSetting:switchTab(tabName)
    if tabName ~= "Password" and not isUnlocked() then
        UIHelper.showToast("Enter the password")
        return
    end

    local oldTab = self.currentTab
    if oldTab == tabName then return end

    local oldContent = self.tabs[oldTab] and self.tabs[oldTab].content
    local newContent = self.tabs[tabName].content

    newContent:SetVisible(true)
    newContent:SetXPosition({0, 620})

    startAnimation({
        duration = 0.2,
        easing = easeOutQuad,
        update = function(progress)
            if oldContent then
                oldContent:SetXPosition({0, -620 * progress})
            end
            newContent:SetXPosition({0, 620 * (1 - progress)})
        end,
        onComplete = function()
            if oldContent then oldContent:SetVisible(false) end
            newContent:SetXPosition({0, 0})

            for name, data in pairs(self.tabs) do
                if name == tabName then
                    data.button:SetBackgroundColor(COLORS.CLOR_6)
                    data.button:SetTextColor(COLORS.CLOR_7)
                    self.dynamicElements.activeTabButton = data.button
                else
                    data.button:SetBackgroundColor(COLORS.CLOR_5)
                    data.button:SetTextColor(COLORS.CLOR_8)
                end
            end
            self.currentTab = tabName
        end
    })
end

function XPSetting:addLabel(tabName, text, x, y, w, h)
    local parent = self.tabs[tabName] and self.tabs[tabName].content
    if not parent then print("XPSetting Error: Tab '" .. tabName .. "' not found.") return end

    local label = GUIManager:createGUIWindow(GUIType.StaticText, "Label_" .. math.random(1, 9999))
    label:SetText(text)
    label:SetWidth({0, w})
    label:SetHeight({0, h})
    label:SetXPosition({0, x})
    label:SetYPosition({0, y})
    label:SetTextColor(COLORS.CLOR_7)
    label:SetBordered(true)
    label:SetProperty("Font", "Arial")
    label:SetTextHorzAlign(HorizontalAlignment.Left)
    parent:AddItem(label)
    return label
end

function XPSetting:addEdit(tabName, defaultText, x, y, w, h)
    local parent = self.tabs[tabName] and self.tabs[tabName].content
    if not parent then print("XPSetting Error: Tab '" .. tabName .. "' not found.") return end
    
    local input = GUIManager:createGUIWindow(GUIType.Edit, "Edit_" .. math.random(1, 9999))
    input:SetText(defaultText or "")
    input:SetWidth({0, w})
    input:SetHeight({0, h})
    input:SetXPosition({0, x})
    input:SetYPosition({0, y})
    input:SetTextColor(COLORS.CLOR_7)
    input:SetBackgroundColor(COLORS.CLOR_8)
    input:SetBordered(true)
    input:SetProperty("Font", "Arial")
    input:SetCaratOffset(5)
    input:SetMaxLength(100)
    parent:AddItem(input)
    return input
end

function XPSetting:addItem(tabName, itemName, callbackOrFuncName)
    local tabData = self.tabs[tabName]
    local parent = tabData and tabData.content
    if not parent then print("XPSetting Error: Tab '" .. tabName .. "' not found.") return end

    local itemW = 135
    local itemH = 40
    local spacing = 5
    local panelWidth = 620

    if (tabData.nextX + itemW) > panelWidth then
        tabData.nextX = 10
        tabData.nextY = tabData.nextY + itemH + spacing
    end

    local currentX = tabData.nextX
    local currentY = tabData.nextY

    tabData.nextX = tabData.nextX + itemW + spacing

    local button = GUIManager:createGUIWindow(GUIType.StaticText, "Item_" .. math.random(1, 9999))
    button:SetText("" .. itemName .. "")
    button:SetWidth({0, itemW})
    button:SetHeight({0, itemH})
    button:SetXPosition({0, currentX})
    button:SetYPosition({0, currentY})
    button:SetBordered(true)
    button:SetProperty("Font", "Arial")
    button:SetTextHorzAlign(HorizontalAlignment.Center)
    button:SetTextColor(COLORS.CLOR_8)

    local normalColor = COLORS.CLOR_3
    local hoverColor = COLORS.CLOR_4
    button:SetBackgroundColor(normalColor)

    button:registerEvent(GUIEvent.FocusChange, function(isFocused)
        if isFocused then
            button:SetBackgroundColor(hoverColor)
            startAnimation({
                duration = 0.1,
                update = function(p)
                    local scale = 1 + 0.05 * p
                    button:SetScale(VectorUtil.newVector3(scale, scale, scale))
                end,
                onComplete = function()
                    button:SetScale(VectorUtil.newVector3(1.05, 1.05, 1.05))
                end
            })
        else
            button:SetBackgroundColor(normalColor)
            startAnimation({
                duration = 0.1,
                update = function(p)
                    local scale = 1.05 - 0.05 * p
                    button:SetScale(VectorUtil.newVector3(scale, scale, scale))
                end,
                onComplete = function()
                    button:SetScale(VectorUtil.newVector3(1, 1, 1))
                end
            })
        end
    end)
    
    parent:AddItem(button)

    if callbackOrFuncName then
        button:registerEvent(GUIEvent.Click, function()
            button:SetScale(VectorUtil.newVector3(0.95, 0.95, 0.95))
            LuaTimer:scheduleTimer(function()
                if button then button:SetScale(VectorUtil.newVector3(1, 1, 1)) end
            end, 80, 1)

            if type(callbackOrFuncName) == "function" then
                callbackOrFuncName(button)
            elseif type(callbackOrFuncName) == "string" then
                local func = XPHelper[callbackOrFuncName]
                
                if type(func) == "function" then
                    func(XPHelper, button)
                else
                    UIHelper.showToast("XPHelper Error: Function '" .. callbackOrFuncName .. "' not found.")
                    
                end
            end
        end)
    end
    
    return button
end

function XPSetting:toggle()
    if not self.dialog then
        print("XPSetting Error: Menu chưa được khởi tạo.")
        return
    end
    
    local isVisible = not self.dialog:IsVisible()
    
    if isVisible then
        if not isUnlocked() then
            isPasswordCorrect = false
            unlockUntil = 0
            self.currentTab = "Password"
        end
    end
    
    if isVisible and self.isMinimized then
        self.tabContainer:SetVisible(true)
        self.contentContainer:SetVisible(true)
        self.dialog:SetHeight(self.originalDialogHeight)
        self.isMinimized = false
        if self.dynamicElements.minimizeButton then
            self.dynamicElements.minimizeButton:SetText("—")
        end
    end
    
    self:animateScale(self.dialog, isVisible)

    if isVisible then
        self:switchTab(self.currentTab)
        toggleTitleAnimation(true)
    else
        toggleTitleAnimation(false)
    end
end

local function createPasswordKeyboard(parent, editBox)
    local keys = {
        {"Q","W","E","R","T","Y","U","I","O","P"},
        {"A","S","D","F","G","H","J","K","L"},
        {"Z","X","C","V","B","N","M"},
        {"1","2","3","4","5","6","7","8","9","0"},
        {"Backspace", "Clear", "Enter"}
    }
    local startX = 10
    local startY = 110
    local keyH = 50
    local spacing = 5

    local function getKeyWidth(key)
        if key == "Backspace" or key == "Clear" or key == "Enter" then
            return 80
        else
            return 50
        end
    end

    for rowIdx, row in ipairs(keys) do
        local y = startY + (rowIdx-1) * (keyH + spacing)
        local x = startX
        for _, key in ipairs(row) do
            local w = getKeyWidth(key)
            local btn = GUIManager:createGUIWindow(GUIType.StaticText, "Key_" .. key .. "_" .. math.random(1,9999))
            btn:SetText(key)
            btn:SetWidth({0, w})
            btn:SetHeight({0, keyH})
            btn:SetXPosition({0, x})
            btn:SetYPosition({0, y})
            btn:SetBordered(true)
            btn:SetProperty("Font", "Arial")
            btn:SetTextHorzAlign(HorizontalAlignment.Center)
            btn:SetTextColor(COLORS.CLOR_8)
            btn:SetBackgroundColor(COLORS.CLOR_3)
            parent:AddItem(btn)

            btn:registerEvent(GUIEvent.FocusChange, function(isFocused)
                if isFocused then
                    btn:SetBackgroundColor(COLORS.CLOR_4)
                else
                    btn:SetBackgroundColor(COLORS.CLOR_3)
                end
            end)

            btn:registerEvent(GUIEvent.Click, function()
                btn:SetScale(VectorUtil.newVector3(0.95, 0.95, 0.95))
                LuaTimer:scheduleTimer(function()
                    if btn then btn:SetScale(VectorUtil.newVector3(1, 1, 1)) end
                end, 80, 1)

                if key == "Backspace" then
                    local text = editBox:GetText()
                    if #text > 0 then
                        editBox:SetText(text:sub(1, -2))
                    end
                elseif key == "Clear" then
                    editBox:SetText("")
                elseif key == "Enter" then
                    local entered = editBox:GetText()
                    if entered == PASSWORD then
                        setUnlocked(3600)
                        UIHelper.showToast("Password correct! Unlocked for 3 hours.")
                        XPSetting:switchTab("hacks")
                    else
                        UIHelper.showToast("Incorrect password")
                    end
                else
                    local text = editBox:GetText()
                    editBox:SetText(text .. key)
                end
            end)

            x = x + w + spacing
        end
    end
end

local function initializeXPSetting()
    XPSetting:addTab("Password")
    XPSetting:addTab("hacks")
    XPSetting:addTab("effects")
    XPSetting:addTab("buggy")
    XPSetting:addTab("Game & Panel")
    XPSetting:addTab("mods")
    XPSetting:addTab("Credits")
    
    local passwordEdit = XPSetting:addEdit("Password", "", 10, 10, 400, 40)
    local passTab = XPSetting.tabs["Password"]
    passTab.nextX = 10
    passTab.nextY = 60
    XPSetting:addItem("Password", "Submit", function()
        local entered = passwordEdit:GetText()
        if entered == PASSWORD then
            setUnlocked(300)
            UIHelper.showToast("Password correct! Unlocked for 5 minutes.")
            XPSetting:switchTab("hacks")
        else
            UIHelper.showToast("Incorrect password")
        end
    end)

    local passContent = XPSetting.tabs["Password"].content
    createPasswordKeyboard(passContent, passwordEdit)
    
    XPSetting:addItem("hacks", "Unlimited Jumps", "unlimitedJumps")
    XPSetting:addItem("hacks", "Reach", "Reach")
    XPSetting:addItem("hacks", "Bow Speed", "BowSpeed")
    XPSetting:addItem("hacks", "AttacksCD", "BanClickCD")
    XPSetting:addItem("hacks", "Quick Break", "quickBreak")
    XPSetting:addItem("hacks", "Free Cam", "FreeCam")
    XPSetting:addItem("hacks", "Respawn", "Respawn")
    XPSetting:addItem("hacks", "Dev Fly", "DevFly")
    XPSetting:addItem("hacks", "High Jumper", "JumpHeight")
    XPSetting:addItem("hacks", "Speed Manager", "SpeedManager")
    XPSetting:addItem("hacks", "No Fall", "NoFall")
    XPSetting:addItem("hacks", "Quick Block", "quickblock")
    XPSetting:addItem("hacks", "Fly Parachute", "FlyParachute")
    XPSetting:addItem("hacks", "OP Blink", "BlinkOP")
    XPSetting:addItem("hacks", "Aim Bot", "AimBot")
    XPSetting:addItem("hacks", "Tracer", "Tracer")
    XPSetting:addItem("hacks", "Hit Box", "Hitbox")
    XPSetting:addItem("hacks", "Auto Click", "AutoClick")
    
    XPSetting:addItem("effects", "Hide Names", "HideNames")
    XPSetting:addItem("effects", "Change Name", "ChangeName")
    XPSetting:addItem("effects", "XRay All", "XRayAll")
    XPSetting:addItem("effects", "Max FPS", "MaxFPS")
    XPSetting:addItem("effects", "WWE Cam", "WWE_Cam")
    XPSetting:addItem("effects", "Run Code", "runCode")
    
    XPSetting:addItem("buggy", "Noclip", "Noclip")
    
    XPSetting:addItem("Game & Panel", "DDOS / Lag Server", "LagServer2")
    XPSetting:addItem("Game & Panel", "Re-enter", "reEnter")
    XPSetting:addItem("Game & Panel", "Close Game", "closeGame")
    XPSetting:addItem("Game & Panel", "Remove Panel", "removePanel")
    
    XPSetting:addItem("mods", "Skins For Player", "RunCode")
    XPSetting:addItem("mods", "Crazy Mode", "CrazyMode")
    
    local effectParent = XPSetting.tabs["effects"].content
    local outBox = GUIManager:createGUIWindow(GUIType.StaticText, "XP_Output")
    outBox:SetText("")
    outBox:SetWidth({1, -20})
    outBox:SetHeight({0, 80})
    outBox:SetXPosition({0, 10})
    outBox:SetYPosition({0, 350})
    outBox:SetTextColor(COLORS.CLOR_6)
    outBox:SetBordered(true)
    outBox:SetProperty("Font", "Arial")
    outBox:SetTextHorzAlign(HorizontalAlignment.Left)
    outBox:SetBackgroundColor(COLORS.CLOR_7)
    outBox:SetTextVertAlign(VerticalAlignment.Top)
    outBox:SetProperty("HorzWrap", "true")
    effectParent:AddItem(outBox)
    outBox:registerEvent(GUIEvent.Click, function()
        local output = outBox:GetText()
        if output and output ~= "" then
            ClientHelper.onSetClipboard(output)
            UIHelper.showToast("Copied to clipboard.")
        end
    end)
    
    local credLabel1 = XPSetting:addLabel("Credits", "Credits : Xojas Panel", 10, 20, 600, 40)
    credLabel1:SetTextHorzAlign(HorizontalAlignment.Center)
    
    local credLabel2 = XPSetting:addLabel("Credits", "Xojas GUI By shadowdev", 10, 60, 600, 40)
    credLabel2:SetTextHorzAlign(HorizontalAlignment.Center)
    
    local credLabel3 = XPSetting:addLabel("Credits", "Encrypted : shadowdev", 10, 100, 600, 40)
    credLabel3:SetTextHorzAlign(HorizontalAlignment.Center)
    
    local credLabel4 = XPSetting:addLabel("Credits", "Gui Version : [ version 0.4a ]", 10, 140, 600, 40)
    credLabel4:SetTextHorzAlign(HorizontalAlignment.Center)
    
if not GMHelper.OpenDiscordLink then
    function GMHelper:OpenDiscordLink()
        local discordLink = "https://discord.gg/yBpKbrPQs"  -- <-- REPLACE WITH YOUR DISCORD INVITE
        UIHelper.showToast("Opening Discord server...")
        
        local success, err = pcall(function()
            discord(discordLink)
        end)
        
        if success then
            UIHelper.showToast("Discord opened successfully!")
            return true
        else
            UIHelper.showToast("Failed to open Discord: " .. (err or "Unknown error"))
            return false
        end
    end
end

local creditsContent = XPSetting.tabs["Credits"].content
local discordBtn = GUIManager:createGUIWindow(GUIType.StaticText, "DiscordBtn")
discordBtn:SetText("Join our Discord")
discordBtn:SetWidth({0, 600})
discordBtn:SetHeight({0, 40})
discordBtn:SetXPosition({0, 10})
discordBtn:SetYPosition({0, 180})
discordBtn:SetBordered(true)
discordBtn:SetProperty("Font", "Arial")
discordBtn:SetTextHorzAlign(HorizontalAlignment.Center)
discordBtn:SetTextColor(COLORS.CLOR_8)
discordBtn:SetBackgroundColor(COLORS.CLOR_3)
creditsContent:AddItem(discordBtn)

-- Hover effect
discordBtn:registerEvent(GUIEvent.FocusChange, function(isFocused)
    if isFocused then
        discordBtn:SetBackgroundColor(COLORS.CLOR_4)
        startAnimation({
            duration = 0.1,
            update = function(p)
                local scale = 1 + 0.05 * p
                discordBtn:SetScale(VectorUtil.newVector3(scale, scale, scale))
            end,
            onComplete = function()
                discordBtn:SetScale(VectorUtil.newVector3(1.05, 1.05, 1.05))
            end
        })
    else
        discordBtn:SetBackgroundColor(COLORS.CLOR_3)
        startAnimation({
            duration = 0.1,
            update = function(p)
                local scale = 1.05 - 0.05 * p
                discordBtn:SetScale(VectorUtil.newVector3(scale, scale, scale))
            end,
            onComplete = function()
                discordBtn:SetScale(VectorUtil.newVector3(1, 1, 1))
            end
        })
    end
end)

-- Click event
discordBtn:registerEvent(GUIEvent.Click, function()
    discordBtn:SetScale(VectorUtil.newVector3(0.95, 0.95, 0.95))
    LuaTimer:scheduleTimer(function()
        if discordBtn then discordBtn:SetScale(VectorUtil.newVector3(1, 1, 1)) end
    end, 80, 1)
    GMHelper:OpenDiscordLink()
end)

if not GMHelper.OpenYouTubeLink then
    function GMHelper:OpenYouTubeLink()
        local youtubeLink = "https://youtube.com/@shadowdev_dsh?si=0-DLfO3getZoiTQD"  -- <-- REPLACE WITH YOUR YOUTUBE CHANNEL LINK
        UIHelper.showToast("Opening YouTube channel...")
        
        -- Use the same discord() function – it might handle any URL
        local success, err = pcall(function()
            discord(youtubeLink)
        end)
        
        if success then
            UIHelper.showToast("YouTube opened successfully!")
            return true
        else
            -- Fallback: copy link to clipboard so user can paste manually
            ClientHelper.onSetClipboard(youtubeLink)
            UIHelper.showToast("Couldn't open automatically. Link copied to clipboard.")
            return false
        end
    end
end

local youtubeBtn = GUIManager:createGUIWindow(GUIType.StaticText, "YouTubeBtn")
youtubeBtn:SetText("Subscribe on YouTube")
youtubeBtn:SetWidth({0, 600})
youtubeBtn:SetHeight({0, 40})
youtubeBtn:SetXPosition({0, 10})
youtubeBtn:SetYPosition({0, 230})  -- below Discord button
youtubeBtn:SetBordered(true)
youtubeBtn:SetProperty("Font", "Arial")
youtubeBtn:SetTextHorzAlign(HorizontalAlignment.Center)
youtubeBtn:SetTextColor(COLORS.CLOR_8)
youtubeBtn:SetBackgroundColor(COLORS.CLOR_3)
creditsContent:AddItem(youtubeBtn)

-- Hover effect
youtubeBtn:registerEvent(GUIEvent.FocusChange, function(isFocused)
    if isFocused then
        youtubeBtn:SetBackgroundColor(COLORS.CLOR_4)
        startAnimation({
            duration = 0.1,
            update = function(p)
                local scale = 1 + 0.05 * p
                youtubeBtn:SetScale(VectorUtil.newVector3(scale, scale, scale))
            end,
            onComplete = function()
                youtubeBtn:SetScale(VectorUtil.newVector3(1.05, 1.05, 1.05))
            end
        })
    else
        youtubeBtn:SetBackgroundColor(COLORS.CLOR_3)
        startAnimation({
            duration = 0.1,
            update = function(p)
                local scale = 1.05 - 0.05 * p
                youtubeBtn:SetScale(VectorUtil.newVector3(scale, scale, scale))
            end,
            onComplete = function()
                youtubeBtn:SetScale(VectorUtil.newVector3(1, 1, 1))
            end
        })
    end
end)

-- Click event
youtubeBtn:registerEvent(GUIEvent.Click, function()
    youtubeBtn:SetScale(VectorUtil.newVector3(0.95, 0.95, 0.95))
    LuaTimer:scheduleTimer(function()
        if youtubeBtn then youtubeBtn:SetScale(VectorUtil.newVector3(1, 1, 1)) end
    end, 80, 1)
    GMHelper:OpenYouTubeLink()
end)
    
    local creditLabels = {credLabel1, credLabel2, credLabel3, credLabel4}
    local creditColorTimer = nil
    
    local function updateCreditColors()
        local r, g, b = HSVtoRGB()
        local color = {r, g, b, 1}
        for _, label in ipairs(creditLabels) do
            if label then
                label:SetTextColor(color)
            end
        end
    end
    
    local function toggleCreditAnimation(start)
        if start then
            if not creditColorTimer then
                updateCreditColors()
                creditColorTimer = LuaTimer:scheduleTimer(updateCreditColors, 50, -1)
            end
        else
            if creditColorTimer then
                LuaTimer:cancel(creditColorTimer)
                creditColorTimer = nil
            end
        end
    end
    
    local originalSwitchTab = XPSetting.switchTab
    function XPSetting:switchTab(tabName)
        if self.currentTab == "Credits" and tabName ~= "Credits" then
            toggleCreditAnimation(false)
        end
        originalSwitchTab(self, tabName)
        if tabName == "Credits" then
            toggleCreditAnimation(true)
        end
    end
    
    local originalToggle = XPSetting.toggle
    function XPSetting:toggle()
        local isVisible = not (self.dialog and self.dialog:IsVisible())
        if not isVisible and self.currentTab == "Credits" then
            toggleCreditAnimation(false)
        end
        originalToggle(self)
        if isVisible and self.currentTab == "Credits" then
            toggleCreditAnimation(true)
        end
    end
    
    XPSetting:switchTab("Password")
end

function ToggleXPMenu()
    if not XPSetting.dialog then
        initializeXPSetting()
    end

    if XPSetting.dialog:IsVisible() then
        XPSetting:toggle()
    else
        if not isUnlocked() then
            isPasswordCorrect = false
            unlockUntil = 0
            XPSetting.currentTab = "Password"
        end
        XPSetting:toggle()
    end
end

function Credit()
    local GUI = GUIManager:createGUIWindow(GUIType.StaticText, "GUIRootMG")
    GUI:SetVisible(true)
    GUI:SetBordered(true)
    GUI:SetTouchable(false)
    GUI:SetHorizontalAlignment(HorizontalAlignment.Center)
    GUI:SetTextHorzAlign(HorizontalAlignment.Center)
    GUI:SetWidth({ 0, 556 })
    GUI:SetHeight({ 0, 30 })
    GUI:SetYPosition({ 0, 120 })
    GUI:SetTextScale(1.0)
    GUISystem.Instance():GetRootWindow():AddChildWindow(GUI)
    local function Update()
        -- Updated version string to "Shadow dev version 0.4a"
        local text = "Xojas Panel [Gui version 0.4a] {Creator: shadowdev}"
        GUI:SetText(text)
        local r, g, b = HSVtoRGB()
        GUI:SetTextColor({ r, g, b, 0.8 })
    end
    LuaTimer:scheduleTimer(Update, 16, -1)
end

Credit()

function XPHelper:CrazyMode()
    togCrazyMode = not togCrazyMode
    if togCrazyMode then
        if #uiElements == 0 then
            for _, name in ipairs(mainElements) do
                local el = GUIManager:getWindowByName(name)
                if el then table.insert(uiElements, el) end
            end
        end
        if not crazyAnimHandle then
            crazyAnimHandle = startAnimation({
                duration = 999999,
                update = updateCrazyColors
            })
        end
        UIHelper.showToast("^00FF00Crazy Mode ON")
    else
        if crazyAnimHandle then
            for i, anim in ipairs(activeAnimations) do
                if anim == crazyAnimHandle then
                    table.remove(activeAnimations, i)
                    break
                end
            end
            crazyAnimHandle = nil
        end
        local resetColor = { 0, 0, 0, 1 }
        for _, element in ipairs(uiElements) do
            if element then
                xpcall(function() element:SetDrawColor(resetColor) end, function() end)
            end
        end
        UIHelper.showToast("^FF0000Crazy Mode OFF")
    end
end

function XPHelper:unlimitedJumps()
    togunlimitedJumps = not togunlimitedJumps
    ClientHelper.putBoolPrefs("EnableDoubleJumps", true)
    PlayerManager:getClientPlayer().doubleJumpCount = 10000
    if togunlimitedJumps then
        UIHelper.showToast("^00FF00FLy ON")
        return
    end
    ClientHelper.putBoolPrefs("EnableDoubleJumps", false)
    UIHelper.showToast("^FF0000FLy OFF")
end

function XPHelper:Reach()
    togReach = not togReach
    ClientHelper.putFloatPrefs("BlockReachDistance", 999)
    ClientHelper.putFloatPrefs("EntityReachDistance", 7)
    if togReach then
        UIHelper.showToast("^00FF00REACH ON")
        return
    end
    ClientHelper.putFloatPrefs("BlockReachDistance", 6.5)
    ClientHelper.putFloatPrefs("EntityReachDistance", 5)
    UIHelper.showToast("^00FF00REACH OFF")
end

function XPHelper:BowSpeed()
    togBowSpeed = true
    ClientHelper.putFloatPrefs("BowPullingSpeedMultiplier", 1000)
    ClientHelper.putFloatPrefs("BowPullingFOVMultiplier", 0)
    UIHelper.showToast("^00FF00BowSpeed:ON")
end

function XPHelper:HideNames()
    togHideNames = not togHideNames
    ClientHelper.putBoolPrefs("RenderHeadText", false)
    if togHideNames then
        UIHelper.showToast("^00FF00Hide Names ON")
        return
    end
    ClientHelper.putBoolPrefs("RenderHeadText", true)
    UIHelper.showToast("^FF0000Hide names OFF")
end

function XPHelper:BanClickCD()
    togBanClickCD = not togBanClickCD
    ClientHelper.putBoolPrefs("banClickCD", true)
    ClientHelper.putBoolPrefs("RemoveClickCD", true)
    ClientHelper.putIntPrefs("HurtProtectTime", 0)
    ClientHelper.putBoolPrefs("BanEntityHitCD", true)
    ClientHelper.putIntPrefs("ClickSceneCD", 0)
    PlayerManager:getClientPlayer().Player:setIntProperty("bedWarAttackCD", 0)
    UIHelper.showToast("^00FF00NoDelay ON!")
    if not togBanClickCD then
        ClientHelper.putBoolPrefs("banClickCD", false)
        ClientHelper.putBoolPrefs("RemoveClickCD", false)
        ClientHelper.putIntPrefs("HurtProtectTime", 5)
        ClientHelper.putBoolPrefs("BanEntityHitCD", false)
        ClientHelper.putIntPrefs("ClickSceneCD", 5)
        PlayerManager:getClientPlayer().Player:setIntProperty("bedWarAttackCD", 5)
        UIHelper.showToast("^FF0000NoDelay OFF!")
    end
end

function XPHelper:quickBreak()
    togquickBreak = true
    cBlockManager.cGetBlockById(66):setNeedRender(false)
    cBlockManager.cGetBlockById(253):setNeedRender(false)
    for blockId = 1, 40000 do
        local block = BlockManager.getBlockById(blockId)
        if block then
            block:setHardness(0)
            UIHelper.showToast("^00FF00Fast Break ON")
        end
    end
end

function XPHelper:FreeCam()
    togFreeCam = true
    GUIManager:getWindowByName("Main-HideAndSeek-Operate"):SetVisible(true)
    GUIGMControlPanel1:hide()
end

function XPHelper:Respawn()
    PacketSender:getSender():sendRebirth()
end

function XPHelper:DevFly()
    local moveDir = VectorUtil.newVector3(0.0, 1.35, 0.0)
    local player = PlayerManager:getClientPlayer()
    player.Player:setAllowFlying(true)
    player.Player:setFlying(true)
    player.Player:moveEntity(moveDir)
    UIHelper.showToast("^FF00EESuccess")
end

function XPHelper:JumpHeight()
    togJumpHeight = not togJumpHeight
    local player = PlayerManager:getClientPlayer()
    if player and player.Player then
        if togJumpHeight then
            player.Player:setFloatProperty("JumpHeight", 1)
            UIHelper.showToast("^00FF00[ON]")
            return
        end
        player.Player:setFloatProperty("JumpHeight", 0.4)
        UIHelper.showToast("^00FF00[OFF]")
    end
end

function XPHelper:SpeedManager()
    togSpeedManager = not togSpeedManager
    if togSpeedManager then
        PlayerManager:getClientPlayer().Player:setSpeedAdditionLevel(300000)
        UIHelper.showToast("^FF00EEON")
        return
    end
    PlayerManager:getClientPlayer().Player:setSpeedAdditionLevel(0)
    UIHelper.showToast("^FF00EEOFF")
end

function XPHelper:XRayAll()
    togXRayAll = not togXRayAll
    for blockId = 1, 40000 do
        block = cBlockManager.cGetBlockById(blockId)
        if block ~= nil then
            block:setNeedRender(not togXRayAll)
        end
    end
    UIHelper.showToast("^FF00EESuccess")
end

function XPHelper:NoFall()
    togNoFall = not togNoFall
    ClientHelper.putIntPrefs("SprintLimitCheck", 7)
    if togNoFall then
        UIHelper.showToast("^FF00EE[ON]")
        return
    end
    ClientHelper.putIntPrefs("SprintLimitCheck", 0)
    UIHelper.showToast("^FF00EEOFF")
end

function XPHelper:quickblock()
    GMHelper:openInput({ "" }, function(Number)
        ClientHelper.putIntPrefs("QuicklyBuildBlockNum", Number)
        UIHelper.showToast("^FF00EESuccess")
    end)
end

function XPHelper:FlyParachute()
    local moveDir = VectorUtil.newVector3(0.0, 1.35, 0.0)
    local player = PlayerManager:getClientPlayer()
    player.Player:setAllowFlying(true)
    player.Player:setFlying(true)
    player.Player:moveEntity(moveDir)
    PlayerManager:getClientPlayer().Player:startParachute()
    UIHelper.showToast("^FF00EESuccess")
end

function XPHelper:BW()
    togBW = true
    ClientHelper.putIntPrefs("ClientHelper.RunLimitCheck", 0)
    ClientHelper.putIntPrefs("ClientHelper.SprintLimitCheck", 0)
    UIHelper.showToast("^FF00EESuccess")
end

function XPHelper:BlinkOP()
    togBlinkOP = not togBlinkOP
    ClientHelper.putBoolPrefs("SyncClientPositionToServer", false)
    if togBlinkOP then
        UIHelper.showToast("^00FF00Blink Enabled!")
        return
    end
    ClientHelper.putBoolPrefs("SyncClientPositionToServer", true)
    UIHelper.showToast("^FF0000Blink Disabled!")
end

function XPHelper:AimBot()
    togAimBot = not togAimBot
    if not togAimBot then
        LuaTimer:cancel(aimTimer)
        UIHelper.showToast("^FF0000AimBot OFF!")
        return
    end
    local function getPitchAndYaw(targetPos)
        local camera = SceneManager.Instance():getMainCamera()
        local pos = camera:getPosition()
        local vector = math.atan2(targetPos.x - pos.x, targetPos.z - pos.z)
        local yaw = vector / math.pi * -180

        local dir = VectorUtil.sub3(targetPos, pos)
        local pitch = MathUtil.GetVector3Angle(VectorUtil.newVector3(dir.x, 0, dir.z), dir)

        return yaw, pitch
    end

    aimTimer = LuaTimer:scheduleTimer(function()
        local clientPlayer = PlayerManager:getClientPlayer().Player
        local players = PlayerManager:getPlayers()

        local recentDistance = 12
        local closestPlayer

        for _, c_player in pairs(players) do
            if clientPlayer:getTeamId() ~= c_player:getTeamId() then
                local playerPos = clientPlayer:getPosition()
                local entityPos = c_player:getPosition()
                local distance = distanceM(entityPos, playerPos)

                if distance < recentDistance and distance ~= 0 then
                    MsgSender.sendMsg(tostring(distance))
                    recentDistance = distance
                    closestPlayer = c_player
                end
            end

            if closestPlayer then
                local playerPos = clientPlayer:getPosition()
                local closestPlayerPos = closestPlayer:getPosition()
                closestPlayerPos.y = closestPlayerPos.y + 1
                yaw, pitch = getPitchAndYaw(closestPlayerPos)
                clientPlayer.rotationYaw, clientPlayer.rotationPitch = yaw, pitch
            end
        end
    end, 0.75, -1)
    UIHelper.showToast("^FF0000AimBot ON!")
end

function XPHelper:WWE_Cam()
    togWWE_Cam = not togWWE_Cam
    ClientHelper.putBoolPrefs("IsSeparateCamera", true)
    if togWWE_Cam then
        UIHelper.showToast("^00FF00SeparateCamera: Enabled")
        return
    end
    ClientHelper.putBoolPrefs("IsSeparateCamera", false)
    UIHelper.showToast("^FF0000SeparateCamera: Disabled")
end

function XPHelper:Tracer()
    togTracer = not togTracer
    if not togTracer then
        LuaTimer:cancel(tracerTimer)
        PlayerManager.getClientPlayer().Player:deleteAllGuideArrow()
        UIHelper.showToast("^FF0000Tracer: Disabled")
        return
    end
    local me = PlayerManager:getClientPlayer()
    tracerTimer = LuaTimer:scheduleTimer(function()
        PlayerManager.getClientPlayer().Player:deleteAllGuideArrow()
        local others = PlayerManager:getPlayers()
        for _, c_player in pairs(others) do
            if c_player ~= me then
                me.Player:addGuideArrow(c_player:getPosition())
            end
        end
    end, 500, -1)
    UIHelper.showToast("^FF00EE[ON]")
end

function XPHelper:HitBox()
    togHitBox = not togHitBox
    local players = PlayerManager:getPlayers()
    for _, player in ipairs(players) do
        local entity = player.Player
        local clientPlayer = PlayerManager:getClientPlayer()

        if player ~= clientPlayer and clientPlayer.Player:getTeamId() ~= player:getTeamId() then
            if togHitBox then
                entity.height = 10
                entity.width = 10
                entity.lenght = 10
                UIHelper.showToast("^FF00EE[ON]")
            else
                entity.height = 1.8
                entity.width = 0.6
                entity.lenght = 0.6
                UIHelper.showToast("^00FF00[OFF]")
            end
        end
    end
end

function XPHelper:AutoClick()
    EntityCache:onTick()
    togAutoClick = not togAutoClick
    if togAutoClick then
        UIHelper.showToast("^FF00EE[ON]")
        GUIGMControlPanel1:hide()
        return
    end
    UIHelper.showToast("^00FF00[OFF]")
end

function XPHelper:Noclip()
    togNoclip = not togNoclip

    for blockId = 1, 40000 do
        local block = BlockManager.getBlockById(blockId)
        if block then
            block:setBlockBounds(0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
        end
    end
    PlayerManager:getClientPlayer().Player.noClip = true

    if togNoclip then
        UIHelper.showToast("^00FF00Noclip = true")
        return
    end
    for blockId = 1, 40000 do
        local block = BlockManager.getBlockById(blockId)
        if block then
            block:setBlockBounds(0.0, 0.0, 0.0, 1.0, 1.0, 1.0)
        end
    end
    PlayerManager:getClientPlayer().Player.noClip = false
    UIHelper.showToast("^FF0000Noclip = false")
end

function XPHelper:closeGame()
    UIHelper.showToast("^FF0000Bye")
    CGame.Instance():exitGame("normal")
end

function XPHelper:reEnter()
    gameType = CGame.Instance():getGameType() or "g1001"
    targetId = targetId or Game:getPlatformUserId()
    mapId = mapId or ""
    UIHelper.showToast("^FF0000Resetting...")
    CGame.Instance():resetGame(gameType, targetId, mapId)
end

function XPHelper:LagServer2()
    togLagServer2 = not togLagServer2
    if togLagServer2 then
        ddosTimer = LuaTimer:scheduleTimer(function()
            UIHelper.showToast("^FF0000DDosing")
            for i = 1, 100000 do
                PlayerManager:getClientPlayer():sendPacket({pid="pid"})
            end
        end, 3000, -1)
        return
    end
    LuaTimer:cancel(ddosTimer)
    UIHelper.showToast("^FF0000DDos stopped")
end

function XPHelper:ViewRaket()
    togViewRaket = not togViewRaket
    if not togViewRaket then
        GUIManager:getWindowByName("Main-BuildWar-Block"):SetVisible(false)
        return
    end
    GUIManager:getWindowByName("Main-BuildWar-Block"):SetVisible(true)

    GUIManager:getWindowByName("Main-BuildWar-Block", GUIType.Button):registerEvent(GUIEvent.ButtonClick, function()
        BuildWarBtn = not BuildWarBtn
        if BuildWarBtn == true then
            local moveDir = VectorUtil.newVector3(0.0, 1.35, 0.0)
            local player = PlayerManager:getClientPlayer()

            player.Player:setAllowFlying(true)
            player.Player:setFlying(true)
            player.Player:moveEntity(moveDir)

            PlayerManager:getClientPlayer().Player:setSpeedAdditionLevel(150000)

            UIHelper.showToast("^00FF00ON")
        else
            local player = PlayerManager:getClientPlayer()
            player.Player:setAllowFlying(false)
            player.Player:setFlying(false)

            PlayerManager:getClientPlayer().Player:setSpeedAdditionLevel(0)
            UIHelper.showToast("^00FF00OFF")
        end
    end)
end

function XPHelper:removePanel()
    GUIGMControlPanel1:hide()
    CustomDialog.builder()
        .setContentText('you are about to delete the panel\nif you want to get it again you have to use "panel loader"\nare you sure to continue ?')
        .setRightText(Red .. "Delete")
        .setLeftText(Green .. "Cancel")
        .setRightClickListener(function()
            local suc, err = os.remove("/data/user/0/com.sandboxol.blockymods/app_resources/Media/Scripts/Engine/lua/engine_client/helper/GMHelper.lua")
            if not suc then
                UIHelper.showToast("error: " .. tostring(err))
            end
            UIHelper.showToast("deleted")
        end)
        .setLeftClickListener(function()
            UIHelper.showToast("cancelled")
        end)
        .show()
end

function XPHelper:ChangeName()
    XPSetting:openInput("Enter new name:", "", function(input)
        if input and input ~= "" then
            PlayerManager:getClientPlayer().Player:setName(input)
            UIHelper.showToast("Name changed to: " .. input)
        end
    end)
end

function XPHelper:MaxFPS()
    togMaxFPS = not togMaxFPS
    if togMaxFPS then
        ClientHelper.putIntPrefs("MaxFPS", 999)
        UIHelper.showToast("^00FF00Max FPS: ON")
    else
        ClientHelper.putIntPrefs("MaxFPS", 60)
        UIHelper.showToast("^FF0000Max FPS: OFF")
    end
end

function XPHelper:runCode()
    XPSetting:openInput("Enter Lua code to run:", "", function(input)
        if input and input ~= "" then
            local func, err = load(input)
            if func then
                local success, result = pcall(func)
                if success then
                    UIHelper.showToast("Code executed successfully")
                else
                    UIHelper.showToast("Error: " .. tostring(result))
                end
            else
                UIHelper.showToast("Syntax error: " .. tostring(err))
            end
        end
    end)
end

local function createOpenButton()
    local openBtn = GUIManager:createGUIWindow(GUIType.StaticImage, "OpenBtn")
    if not openBtn then return end
    openBtn:SetWidth({0, 50})
    openBtn:SetHeight({0, 50})
    openBtn:SetYPosition({ 0, 65 })
    openBtn:SetXPosition({ 0.5, -75 })
    openBtn:SetImage("set:gui_inventory_icon.json image:icon_bookrack")
    openBtn:SetTouchable(true)
    openBtn:SetLevel(1)
    GUISystem.Instance():GetRootWindow():AddChildWindow(openBtn)

    openBtn:registerEvent(GUIEvent.Click, ToggleXPMenu)
end

initializeXPSetting()
createOpenButton()
XPSetting.dialog:SetVisible(false)
