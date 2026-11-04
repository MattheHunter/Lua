-- =========================================================
--  MiniOS - serveur de comptes et de messagerie
--  A lancer sur UN ordinateur avance avec un modem :
--      minios_server
--  (renomme-le "startup" pour qu'il demarre tout seul)
--  Les comptes sont ranges dans le fichier "accounts.db".
--  Attention : l'ordinateur doit rester dans un chunk charge,
--  sinon le serveur s'arrete.
-- =========================================================

local AUTH, CHAT = "minios_auth", "minios_chat"
local HOSTNAME = "minios-server"
local ACCOUNTS_FILE = "accounts.db"

-- ===== DEBUT CRYPTO (identique dans minios.lua et minios_server.lua) =====
-- SHA-256 + HMAC-SHA-256 en Lua pur (via la bibliotheque bit32 de CC: Tweaked)
local band, bxor, bnot = bit32.band, bit32.bxor, bit32.bnot
local rshift, rrotate = bit32.rshift, bit32.rrotate

local K = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

local function u32(n)
  return string.char(band(rshift(n, 24), 255), band(rshift(n, 16), 255),
    band(rshift(n, 8), 255), band(n, 255))
end

local function sha256(msg)
  local h0, h1, h2, h3 = 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
  local h4, h5, h6, h7 = 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  local len = #msg
  msg = msg .. "\128" .. string.rep("\0", (55 - len) % 64)
    .. u32(math.floor(len * 8 / 4294967296)) .. u32((len * 8) % 4294967296)

  for i = 1, #msg, 64 do
    local w = {}
    for j = 0, 15 do
      local a, b, c, d = msg:byte(i + j * 4, i + j * 4 + 3)
      w[j] = a * 16777216 + b * 65536 + c * 256 + d
    end
    for j = 16, 63 do
      local s0 = bxor(rrotate(w[j - 15], 7), rrotate(w[j - 15], 18), rshift(w[j - 15], 3))
      local s1 = bxor(rrotate(w[j - 2], 17), rrotate(w[j - 2], 19), rshift(w[j - 2], 10))
      w[j] = (w[j - 16] + s0 + w[j - 7] + s1) % 4294967296
    end
    local a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
    for j = 0, 63 do
      local S1 = bxor(rrotate(e, 6), rrotate(e, 11), rrotate(e, 25))
      local ch = bxor(band(e, f), band(bnot(e), g))
      local t1 = (h + S1 + ch + K[j + 1] + w[j]) % 4294967296
      local S0 = bxor(rrotate(a, 2), rrotate(a, 13), rrotate(a, 22))
      local maj = bxor(band(a, b), band(a, c), band(b, c))
      local t2 = (S0 + maj) % 4294967296
      h, g, f, e = g, f, e, (d + t1) % 4294967296
      d, c, b, a = c, b, a, (t1 + t2) % 4294967296
    end
    h0, h1 = (h0 + a) % 4294967296, (h1 + b) % 4294967296
    h2, h3 = (h2 + c) % 4294967296, (h3 + d) % 4294967296
    h4, h5 = (h4 + e) % 4294967296, (h5 + f) % 4294967296
    h6, h7 = (h6 + g) % 4294967296, (h7 + h) % 4294967296
  end
  return string.format("%08x%08x%08x%08x%08x%08x%08x%08x", h0, h1, h2, h3, h4, h5, h6, h7)
end

local function hexToBin(hex)
  return (hex:gsub("%x%x", function(x) return string.char(tonumber(x, 16)) end))
end

local function hmac(key, msg)
  if #key > 64 then key = hexToBin(sha256(key)) end
  key = key .. string.rep("\0", 64 - #key)
  local ipad, opad = {}, {}
  for i = 1, 64 do
    local b = key:byte(i)
    ipad[i] = string.char(bxor(b, 0x36))
    opad[i] = string.char(bxor(b, 0x5c))
  end
  return sha256(table.concat(opad) .. hexToBin(sha256(table.concat(ipad) .. msg)))
end

math.randomseed((os.epoch and os.epoch("utc") or os.clock() * 1000) % 2147483647 + os.getComputerID())

local function randomHex(n)
  local t = {}
  for i = 1, n do t[i] = string.format("%02x", math.random(0, 255)) end
  return table.concat(t)
end
-- ===== FIN CRYPTO =====

-- ---------------------------------------------------------
--  Modem
-- ---------------------------------------------------------
local function openModem()
  for _, name in ipairs(peripheral.getNames()) do
    if peripheral.getType(name) == "modem" then
      if not rednet.isOpen(name) then rednet.open(name) end
      return true
    end
  end
  return false
end

if not openModem() then
  print("Aucun modem detecte : place un modem contre l'ordinateur.")
  return
end
rednet.host(AUTH, HOSTNAME)

-- ---------------------------------------------------------
--  Comptes : accounts[nom en minuscules] = { name, salt, h }
-- ---------------------------------------------------------
local accounts = {}

local function loadAccounts()
  if not fs.exists(ACCOUNTS_FILE) then return end
  local f = fs.open(ACCOUNTS_FILE, "r")
  local data = textutils.unserialize(f.readAll())
  f.close()
  if type(data) == "table" then accounts = data end
end

local function saveAccounts()
  local f = fs.open(ACCOUNTS_FILE, "w")
  f.write(textutils.serialize(accounts))
  f.close()
end

-- ---------------------------------------------------------
--  Etat : connexions en cours et sessions ouvertes
--  sessions[id de l'ordinateur] = { user, sk (cle de session), c (compteur) }
-- ---------------------------------------------------------
local pending, sessions = {}, {}

local function log(text)
  print(textutils.formatTime(os.time(), true) .. " " .. text)
end

local function reply(id, t) rednet.send(id, t, AUTH) end
local function toChat(id, t) rednet.send(id, t, CHAT) end

local function broadcast(t)
  for id in pairs(sessions) do toChat(id, t) end
end

local function findSession(name)
  for id, s in pairs(sessions) do
    if s.user:lower() == name:lower() then return id, s end
  end
end

-- Verifie qu'un message vient bien d'un utilisateur connecte :
-- signature HMAC avec la cle de session + compteur strictement croissant
-- (empeche de rejouer un message capture par radio).
local function verified(id, m)
  local s = sessions[id]
  if not s or type(m.c) ~= "number" or m.c <= s.c then return nil end
  if (m.to ~= nil and type(m.to) ~= "string") or (m.x ~= nil and type(m.x) ~= "string") then
    return nil
  end
  local sig = hmac(s.sk, table.concat({ m.c, m.t, m.to or "", m.x or "" }, "|"))
  if sig ~= m.s then return nil end
  s.c = m.c
  return s
end

-- ---------------------------------------------------------
--  Traitement des requetes
-- ---------------------------------------------------------
local function onRegister(id, m)
  local user = m.u
  if type(user) ~= "string" or #user < 3 or #user > 16 or not user:match("^[%w_%-]+$") then
    return reply(id, { t = "err", x = "Nom invalide (3-16 car. : lettres, chiffres, _ -)" })
  end
  if type(m.salt) ~= "string" or not m.salt:match("^%x+$") or #m.salt > 64
    or type(m.h) ~= "string" or not m.h:match("^%x+$") or #m.h ~= 64 then
    return reply(id, { t = "err", x = "Requete invalide" })
  end
  if accounts[user:lower()] then
    return reply(id, { t = "err", x = "Ce nom est deja pris" })
  end
  accounts[user:lower()] = { name = user, salt = m.salt, h = m.h }
  saveAccounts()
  log("Nouveau compte : " .. user)
  reply(id, { t = "ok" })
end

local function onHello(id, m)
  local acc = type(m.u) == "string" and accounts[m.u:lower()]
  if not acc then
    return reply(id, { t = "err", x = "Identifiants incorrects" })
  end
  local nonce = randomHex(16)
  pending[id] = { key = m.u:lower(), n = nonce }
  reply(id, { t = "chal", salt = acc.salt, n = nonce })
end

local function onLogin(id, m)
  local p = pending[id]
  pending[id] = nil
  if not p or type(m.p) ~= "string" then
    return reply(id, { t = "err", x = "Identifiants incorrects" })
  end
  local acc = accounts[p.key]
  local sk = hmac(acc.h, p.n)
  if hmac(sk, "login") ~= m.p then
    log("Echec de connexion : " .. acc.name)
    return reply(id, { t = "err", x = "Identifiants incorrects" })
  end
  sessions[id] = { user = acc.name, sk = sk, c = 0 }
  log(acc.name .. " connecte (ordinateur " .. id .. ")")
  reply(id, { t = "ok", user = acc.name })
  broadcast({ t = "sys", x = acc.name .. " s'est connecte" })
end

local function onMsg(id, m)
  local s = verified(id, m)
  if not s then
    return reply(id, { t = "err", x = "Session invalide, reconnecte-toi" })
  end
  local text = (m.x or ""):sub(1, 200)
  if text == "" then return end
  if m.to then
    local tid, ts = findSession(m.to)
    if not tid then
      return reply(id, { t = "err", x = m.to .. " n'est pas connecte" })
    end
    local pkt = { t = "chat", from = s.user, to = ts.user, x = text }
    toChat(tid, pkt)
    if tid ~= id then toChat(id, pkt) end
  else
    broadcast({ t = "chat", from = s.user, x = text })
  end
end

local function onBye(id, m)
  local s = verified(id, m)
  if not s then return end
  sessions[id] = nil
  log(s.user .. " deconnecte")
  broadcast({ t = "sys", x = s.user .. " s'est deconnecte" })
end

local handlers = {
  reg = onRegister, hello = onHello, login = onLogin, msg = onMsg, bye = onBye,
}

loadAccounts()
log("Serveur pret (nom '" .. HOSTNAME .. "', ordinateur " .. os.getComputerID() .. ")")

while true do
  local id, m = rednet.receive(AUTH)
  if type(m) == "table" and handlers[m.t] then
    local ok, err = pcall(handlers[m.t], id, m)
    if not ok then log("Erreur : " .. tostring(err)) end
  end
end
