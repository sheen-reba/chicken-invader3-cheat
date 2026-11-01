--[[ ==========================================================================
  Chicken Invaders 3 (3.85steam) 内存修改器 v2 —— Cheat Engine Lua
  适用: CI3.exe / CI3Easter.exe / CI3Xmas.exe

  用法:
    1) CE 附加到游戏进程，进入关卡
    2) File -> Execute Script 执行本文件（或载入 CI3_cheats.CT 后
       Table -> Show Cheat Table Lua Script -> Execute）

  ★ 数值语义（v2 新增）：
     每个字段是 { init = 初始值, min = 最小值 }
     - init: 脚本第一次执行时写入的值（也就是"设置成多少"）
     - min = nil  → 每 200ms 强制等于 init（锁定）
     - min = 数值 → 每 200ms 只检查：当前值 < min 就改成 min；>= min 就不管
     例:
       CI3MOD.cfg.lives = { init = 99, min = nil }   -- 永远锁 99
       CI3MOD.cfg.lives = { init = 99, min = 30 }    -- 起步 99，掉到 30 以下才补回 30
     改完调用 CI3MOD.restart() 生效。

  ★ 武器等级：**没有 20 级上限**（早前结论有误）。
     实测把等级写成 40：HUD 照实显示，死亡按 max(等级/2, 等级-5) 掉到 31，游戏无报错。
     引擎里 `if (power < 0x14)` / `if (9 < power)` 是"额外特效分支"，不是上限检查。
     真正有区别的是 0..9 这十档弹道；>=10 之后走同一分支。
     脚本默认钳到 0..99（`WLEVEL_MAX`），想更极端可以自己改。

  ★ 武器类型（已验证）：CI3MOD.setWeaponType(t)  t = 0..6
     0=WeaponDefault  1=Neutron  2=Laser  3=Gatling  4=Lightning  5=Plasma  6=Fork
     实现方式：**纯数据写入** 武器对象 +0x2C8 = 类型，然后死亡一次或捡一个武器
     升级道具，引擎会用这个字段作为类型自己重装武器（走游戏自己的线程）。
     实测：2(Laser) -> 6，死亡后变成 Fork，无报错。
     注意：直接调 installWeapon 不可行（要求网络线程本地上下文 THEROLE，会断言崩游戏）。

  ★ 过热（已定位但默认关闭）：
     - 过热槽 = PlayerObject + 0x2C8（float 0..1；注意别和"武器类型"混了：
       武器类型在同偏移但属于 **Weapon** 对象，两者是不同对象上的同名偏移）
     - 过热标志 = PlayerObject + 0x2D0（byte）
     - 写这两个字段会和引擎的过热状态机打架（实测会卡在冷却出不来），
       所以 CFG.overheat.enabled 默认 false，要用需自担风险。
============================================================================ ]]

if CI3MOD then pcall(CI3MOD.stop) end

local CFG = {
  lives       = { init = 99, min = nil },   -- 游戏上限 99
  missiles    = { init = 99, min = nil },   -- 游戏上限 99
  weaponLevel = { init = 20, min = nil },   -- 无硬上限，脚本钳 0..99
  hotkeys     = true,                       -- 注册 Ctrl+1..7 / Ctrl+0 武器热键
  overheat    = {
    -- ⚠ 默认关闭。过热槽/过热标志都已定位，但"写这两个字段"会跟引擎的状态机打架：
    --   * 强清过热标志(PO+0x2D0) → 卡在冷却阶段，永久无法开火
    --   * 把槽(PO+0x2C8)清零       → 同样卡死
    --   * 封顶(>x 压回 x)          → 过热时压在高位反而让它出不了冷却；压太低又会被瞬间冲满
    -- 想试的话把 enabled 改 true，并接受"可能卡住、需要停脚本等它自己冷却"的代价。
    clearOverheatFlag = false,
    gauge = { obj = "player", off = 0x2C8, kind = "float", value = 0.15, mode = "cap" },
    enabled = false,
  },
  interval    = 100,
  verbose     = true,
}

-- 对象内部偏移（三个版本源码相同）
local OFF = {
  po_owner   = 0x2AC,
  po_weapon  = 0x2D4,
  po_overheatFlag = 0x2D0,
  po_heatGauge = 0x2C8,   -- float 0..1 过热槽（实测确认）
  wp_power   = 0x2F8,
  pi_score_k = 0x154, pi_score_v = 0x1D8,
  pi_lives_k = 0x25C, pi_lives_v = 0x2E0,
  pi_food_k  = 0x364, pi_food_v  = 0x3E8,
  pi_miss_k  = 0x46C, pi_miss_v  = 0x4F0,
}

-- 武器等级钳制范围。
-- 注意：**没有 20 级硬上限**（实测把等级写成 40 后，HUD 照实显示，死亡钳制后显示 31，
-- 游戏未报错）。引擎里 `power < 0x14` 和 `9 < power` 是"特效分支"，不是上限检查。
-- 不同档位真正的差别只体现在 0..9 这十种弹道；>=10 之后走同一分支。
local WLEVEL_MIN, WLEVEL_MAX = 0, 99

-- 每个 exe 的常量（RVA = 静态VA - 0x400000）
local BUILDS = {
  ["ci3.exe"]       = { poVt = 0x2D5E70, installWeapon = 0x6BA70 },
  ["ci3easter.exe"] = { poVt = 0x2D5F10, installWeapon = 0x6B9D0 },
  ["ci3xmas.exe"]   = { poVt = 0x2D5EC0, installWeapon = 0x6BA70 },
}

local WEAPON_TYPES = {
  [0] = "WeaponDefault", [1] = "Neutron", [2] = "Laser", [3] = "Gatling",
  [4] = "Lightning", [5] = "Plasma", [6] = "Fork",
}

local state = { base = nil, build = nil, po = {}, lastScan = 0 }

local function log(fmt, ...)
  if CFG.verbose then print(string.format("[CI3MOD] " .. fmt, ...)) end
end

local function u32at(a)
  local ok, v = pcall(readInteger, a)
  if ok and v then return v & 0xFFFFFFFF end
  return nil
end

local function decode(pi, k, v)
  local a, b = u32at(pi + k), u32at(pi + v)
  if a == nil or b == nil then return nil end
  return (a ~ b) & 0xFFFFFFFF
end

local function encode(pi, k, v, target)
  local key = u32at(pi + k)
  if key == nil then return false end
  pcall(writeInteger, pi + v, (key ~ target) & 0xFFFFFFFF)
  return true
end

local function bytesPattern(v)
  local b = {}
  for i = 0, 3 do b[i + 1] = (v >> (i * 8)) & 0xFF end
  return string.format("%02X %02X %02X %02X", b[1], b[2], b[3], b[4])
end

local function locateModule()
  local mods = enumModules()
  if not mods then return nil end
  for i = 1, #mods do
    local name = mods[i].Name or ""
    local short = name:match("([^\\/]+)$") or name
    local key = short:lower()
    if BUILDS[key] then
      local addr = mods[i].Address
      if type(addr) == "string" then addr = getAddressSafe(addr) end
      return addr, key, short
    end
  end
  return nil
end

local function scanPlayerObjects()
  local base, key = locateModule()
  if not base or not key then
    log("找不到游戏主模块（CI3*.exe）")
    return {}
  end
  state.base, state.build = base, key
  local vt = base + BUILDS[key].poVt
  local sl = AOBScan(bytesPattern(vt))
  local out = {}
  if sl then
    for i = 0, sl.Count - 1 do
      local a = getAddressSafe(sl[i])
      if a and u32at(a) == vt then
        local inModule = (a >= base) and (a < base + 0x600000)
        if not inModule then
          local pi = u32at(a + OFF.po_owner)
          local wp = u32at(a + OFF.po_weapon)
          if pi and pi > 0x10000 and pi < 0x80000000 then
            out[#out + 1] = { po = a, pi = pi, weapon = (wp and wp > 0x10000) and wp or 0 }
          end
        end
      end
    end
    sl.destroy()
  end
  return out
end

-- 字段读写抽象：secure = key^value 编码
local function getField(o, field)
  if field == "lives" then return decode(o.pi, OFF.pi_lives_k, OFF.pi_lives_v) end
  if field == "missiles" then return decode(o.pi, OFF.pi_miss_k, OFF.pi_miss_v) end
  if field == "weaponLevel" then
    if o.weapon and o.weapon > 0x10000 then return u32at(o.weapon + OFF.wp_power) end
    return nil
  end
  return nil
end

local function setField(o, field, value)
  if field == "lives" then return encode(o.pi, OFF.pi_lives_k, OFF.pi_lives_v, value) end
  if field == "missiles" then return encode(o.pi, OFF.pi_miss_k, OFF.pi_miss_v, value) end
  if field == "weaponLevel" then
    local v = value
    if v < WLEVEL_MIN then v = WLEVEL_MIN end
    if v > WLEVEL_MAX then v = WLEVEL_MAX end
    if o.weapon and o.weapon > 0x10000 then
      pcall(writeInteger, o.weapon + OFF.wp_power, v)
      return true
    end
    return false
  end
  return false
end

-- 单个字段按 init/min 语义处理
local function applyField(o, field, spec)
  if type(spec) ~= "table" or spec.init == nil and spec.min == nil then return false end
  local cur = getField(o, field)
  if cur == nil then return false end
  if spec.min ~= nil then
    if cur < spec.min then
      return setField(o, field, spec.min)
    end
    return false      -- 大于等于最小值就不动
  end
  -- 没有 min：始终锁 init
  return setField(o, field, spec.init)
end

local function applyOverheat(o)
  local oh = CFG.overheat
  if not oh or oh.enabled == false then return end
  if oh.clearOverheatFlag then
    pcall(writeBytes, o.po + OFF.po_overheatFlag, 1, 0)
  end
  if oh.gauge then
    local g = oh.gauge
    local target = nil
    if g.obj == "weapon" and o.weapon and o.weapon > 0x10000 then target = o.weapon + g.off
    elseif g.obj == "player" then target = o.po + g.off end
    if target then
      if g.mode == "cap" then
        -- 封顶模式：只在"未过热"且当前值超过阈值时压回去；
        -- 一旦引擎已进入过热/冷却阶段（标志=1）就完全不碰，避免卡死冷却状态机
        local flagByte = readBytes(o.po + OFF.po_overheatFlag, 1, true)
        local overheated = flagByte and flagByte[1] == 1
        if not overheated then
          local cur = (g.kind == "float") and readFloat(target) or readInteger(target)
          if cur and cur > g.value then
            if g.kind == "float" then pcall(writeFloat, target, g.value)
            else pcall(writeInteger, target, g.value) end
          end
        end
      else
        if g.kind == "float" then pcall(writeFloat, target, g.value)
        else pcall(writeInteger, target, g.value) end
      end
    end
  end
end

local function apply()
  if #state.po == 0 then return false end
  local any = false
  for _, o in ipairs(state.po) do
    if applyField(o, "lives", CFG.lives) then any = true end
    if applyField(o, "missiles", CFG.missiles) then any = true end
    if applyField(o, "weaponLevel", CFG.weaponLevel) then any = true end
    applyOverheat(o)
  end
  return any
end

-- 首次执行时把 init 值写进去（无论有没有 min）
local function applyInit()
  for _, o in ipairs(state.po) do
    for _, f in ipairs({ "lives", "missiles", "weaponLevel" }) do
      local spec = CFG[f]
      if type(spec) == "table" and spec.init ~= nil then
        setField(o, f, spec.init)
      end
    end
  end
end

local function refreshIfStale()
  local ok = #state.po > 0
  if ok then
    for _, o in ipairs(state.po) do
      local pi = u32at(o.po + OFF.po_owner)
      if pi ~= o.pi then ok = false end
      local wp = u32at(o.po + OFF.po_weapon)
      if wp and wp > 0x10000 then o.weapon = wp end
    end
  end
  local now = os.clock()
  if (not ok) or (now - state.lastScan > 2.0) then
    state.po = scanPlayerObjects()
    state.lastScan = now
  end
end

CI3MOD = {}
CI3MOD.cfg = CFG

function CI3MOD.set(field, initValue, minValue)
  if CFG[field] == nil then return false end
  CFG[field] = { init = initValue, min = minValue }
  log("%s = { init = %s, min = %s }", field, tostring(initValue), tostring(minValue))
  return true
end

function CI3MOD.read()
  local r = {}
  for _, o in ipairs(state.po) do
    r[#r + 1] = {
      po = o.po, pi = o.pi, weapon = o.weapon,
      lives    = getField(o, "lives"),
      missiles = getField(o, "missiles"),
      weaponLevel = getField(o, "weaponLevel"),
      food  = decode(o.pi, OFF.pi_food_k, OFF.pi_food_v),
      score = decode(o.pi, OFF.pi_score_k, OFF.pi_score_v),
      overheatFlag = (function() local b = readBytes(o.po + OFF.po_overheatFlag, 1, true); return (b and b[1]) or -1 end)(),
    }
  end
  return r
end

function CI3MOD.rescan()
  state.po = scanPlayerObjects()
  state.lastScan = os.clock()
  return state.po
end

function CI3MOD.stop()
  if CI3MOD.timer then
    CI3MOD.timer.Enabled = false
    CI3MOD.timer.destroy()
    CI3MOD.timer = nil
    log("已停止")
  end
end

function CI3MOD.start()
  CI3MOD.rescan()
  applyInit()          -- 初始值只在启动时写一次
  if CI3MOD.timer then
    CI3MOD.timer.Enabled = false
    CI3MOD.timer.destroy()
    CI3MOD.timer = nil
  end
  local t = createTimer(nil, false)
  t.Interval = CFG.interval
  t.OnTimer = function()
    pcall(function()
      refreshIfStale()
      apply()
    end)
  end
  t.Enabled = true
  CI3MOD.timer = t
  local function d(s) return s and string.format("init=%s,min=%s", tostring(s.init), tostring(s.min)) or "off" end
  log("已启动 lives[%s] missiles[%s] weaponLevel[%s] 间隔 %dms",
      d(CFG.lives), d(CFG.missiles), d(CFG.weaponLevel), CFG.interval)
end

function CI3MOD.restart()
  CI3MOD.stop()
  CI3MOD.start()
end

-- ==== 武器类型：纯数据写入（已验证可行，不调用任何引擎函数）====
--
-- 机制（静态 + 实测确认）：
--   武器对象 + 0x2C8 = 武器类型（int 0..6）
--   引擎在"重装武器"时会用这个字段当类型参数：
--     * 死亡：PlayerObject::local_onStateChange case 4
--             → FUN_0046ba00(power, [weapon+0x2C8])，等级会被钳成 max(power/2, power-5)
--     * 捡武器升级道具：GameController::tickContents 0x43F930
--             → MOV EDX,[weapon+0x2C8] ; functor+0x10 = EDX ; installWeapon(玩家, EDX, power+1)
--   所以：写 weapon+0x2C8 = 目标类型，然后**死亡一次或捡一个武器升级道具**，
--         引擎就会用它自己的线程把武器重装成目标类型。
--
-- 实测：把 +0x2C8 从 2(Laser/橙色) 改成 6 → 死亡后武器变成 Fork，等级 10，无报错，
--       新武器 vtable RVA = 0x2D7520（与我静态提取的 Fork vtable 一致）。
--
-- 注意：直接调 installWeapon 不可行——它要求 THEROLE（网络线程本地上下文），
--       外部线程拿不到，上次强行调用直接断言崩游戏（THEROLE != NULL）。
local WEAPON_VTABLE_CI3 = {
  [0x2D73A8] = "WeaponDefault", [0x2D7AE8] = "Neutron", [0x2D7800] = "Laser",
  [0x2D7688] = "Gatling",       [0x2D7980] = "Lightning", [0x2D7C50] = "Plasma",
  [0x2D7520] = "Fork",
}

function CI3MOD.weaponTypeName()
  local out = {}
  for i, o in ipairs(state.po) do
    if i <= 1 and o.weapon and o.weapon > 0x10000 then
      local ty = u32at(o.weapon + 0x2C8) or -1
      out[#out + 1] = string.format("weapon=%X 类型(0x2C8)=%d(%s) 等级=%d vtableRVA=0x%X",
        o.weapon, ty, WEAPON_TYPES[ty] or "?", u32at(o.weapon + OFF.wp_power) or -1,
        (u32at(o.weapon) or 0) - state.base)
    end
  end
  return table.concat(out, "\n")
end

-- 引擎上下文诊断（只读，用来解释"为什么不能直接调 installWeapon"）
function CI3MOD.engineContext()
  local base = state.base
  if not base then return false, "未识别主模块" end
  local app = u32at(base + 0x38B4EC)
  if not app or app == 0 then return false, "app==0" end
  local sess = u32at(app + 0x28)
  if not sess or sess == 0 then return false, "(app+0x28)==0" end
  local ctx = u32at(sess + 0xC)
  if not ctx or ctx == 0 then
    return false, "THEROLE==NULL（网络线程本地上下文，外部线程永远为 0）"
  end
  return true, string.format("THEROLE=0x%X", ctx)
end

-- 设置武器类型：只写数据，不调用引擎。
-- 0=WeaponDefault 1=Neutron 2=Laser 3=Gatling 4=Lightning 5=Plasma 6=Fork
-- 写完后需要触发一次"重装"：死亡一次，或捡一个武器升级道具。
function CI3MOD.setWeaponType(t)
  t = tonumber(t)
  if not t or t < 0 or t > 6 then
    log("武器类型必须是 0..6")
    return false
  end
  if #state.po == 0 then CI3MOD.rescan() end
  if #state.po == 0 then
    log("没找到 PlayerObject（要先进关卡）")
    return false
  end
  local n = 0
  for _, o in ipairs(state.po) do
    local wp = o.weapon
    if not wp or wp <= 0x10000 then wp = u32at(o.po + OFF.po_weapon) end
    if wp and wp > 0x10000 then
      pcall(writeInteger, wp + 0x2C8, t)
      o.weapon = wp
      n = n + 1
    end
  end
  log("武器类型已写成 %d(%s)（%d 份副本）。现在去【死亡一次】或【捡一个武器升级道具】触发重装。",
      t, WEAPON_TYPES[t] or "?", n)
  return n > 0
end

function CI3MOD.setWeaponTypeChecked(t)
  return CI3MOD.setWeaponType(t)
end

-- ================= 热键（不用手敲 Lua） =================
-- Ctrl+1..Ctrl+7  → 设置武器类型 0..6
-- Ctrl+0          → 打印当前武器类型/等级
-- 注意：设完类型之后，还要【死亡一次】或【捡一个武器升级道具】才会真正换枪。
function CI3MOD.registerWeaponHotkeys()
  CI3MOD.unregisterWeaponHotkeys()
  if not createHotkey then
    log("当前 CE 不支持 createHotkey")
    return false
  end
  local vks = { VK_1, VK_2, VK_3, VK_4, VK_5, VK_6, VK_7 }
  CI3MOD._hotkeys = {}
  local n = 0
  for i, vk in ipairs(vks) do
    if vk then
      local t = i - 1
      local hk = createHotkey(function()
        pcall(function()
          CI3MOD.setWeaponType(t)
        end)
      end, VK_CONTROL, vk)
      if hk then
        CI3MOD._hotkeys[#CI3MOD._hotkeys + 1] = hk
        n = n + 1
      end
    end
  end
  if VK_0 then
    local hk = createHotkey(function()
      pcall(function() print("[CI3MOD] " .. CI3MOD.weaponTypeName()) end)
    end, VK_CONTROL, VK_0)
    if hk then CI3MOD._hotkeys[#CI3MOD._hotkeys + 1] = hk end
  end
  log("武器热键已注册：Ctrl+1..7 = 类型 0..6，Ctrl+0 = 查看当前武器（设完记得死亡/捡升级道具触发重装）")
  return n > 0
end

function CI3MOD.unregisterWeaponHotkeys()
  if CI3MOD._hotkeys then
    for _, hk in ipairs(CI3MOD._hotkeys) do
      pcall(function() hk.destroy() end)
    end
    CI3MOD._hotkeys = nil
  end
end

-- 探针：把武器/玩家对象里 0x200..0x300 的 float/int 打出来，用于定位过热槽
function CI3MOD.probe()
  local lines = {}
  for i, o in ipairs(state.po) do
    if i <= 1 then
      lines[#lines + 1] = string.format("PO=%X weapon=%X", o.po, o.weapon)
      local wp = o.weapon
      if wp and wp > 0x10000 then
        for off = 0x200, 0x2FC, 4 do
          local f = readFloat(wp + off)
          local iv = readInteger(wp + off)
          if f and iv and (math.abs(f) > 0.0001 or iv ~= 0) then
            lines[#lines + 1] = string.format("  weapon+%X  int=%d  float=%.6f", off, iv, f)
          end
        end
      end
    end
  end
  return table.concat(lines, "\n")
end

-- 自动启动
CI3MOD.start()
do
  local r = CI3MOD.read()
  for i, v in ipairs(r) do
    log("副本%d PO=0x%X PI=0x%X 命数=%s 导弹=%s 武器等级=%s 鸡腿=%s 分数=%s 过热标志=%d",
        i, v.po, v.pi, tostring(v.lives), tostring(v.missiles), tostring(v.weaponLevel),
        tostring(v.food), tostring(v.score), v.overheatFlag)
  end
  if #r == 0 then log("没找到玩家对象：请确认游戏已进入关卡") end
end

-- 注册武器热键（Ctrl+1..7 / Ctrl+0）；不想要就把 CFG.hotkeys 改 false
if CFG.hotkeys ~= false then
  pcall(CI3MOD.registerWeaponHotkeys)
end
