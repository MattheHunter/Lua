-- =========================================================
--  MiniOS - serveur de comptes et de messagerie (v0.4)
--
--  A lancer sur UN ordinateur avance avec un modem :
--      minios_server
--  (renomme-le "startup" pour qu'il demarre tout seul)
--
--  Les comptes sont COMMUNS a tous les ordinateurs MiniOS du
--  monde : ils sont ranges ici, dans "accounts.db".
--  - au premier lancement, tu crees le compte administrateur
--  - les administrateurs gerent ensuite les comptes depuis MiniOS
--  - tout le monde peut creer un compte (non admin) depuis l'ecran
--    de connexion de MiniOS
--  - mot de passe admin perdu : minios_server admin
--
--  L'ordinateur doit rester dans un chunk charge, sinon le
--  serveur s'arrete et plus personne ne peut se connecter.
-- =========================================================

local AUTH, CHAT = "minios_auth", "minios_chat"
local HOSTNAME = "minios-server"
local ACCOUNTS_FILE = "accounts.db"
local MIN_PASSWORD = 4
local args = { ... }

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

-- XOR de deux chaines hexadecimales de meme longueur (chiffrement a cle de session)
local function xorHex(a, b)
  local out = {}
  for i = 1, #a do
    out[i] = string.format("%x", bxor(tonumber(a:sub(i, i), 16), tonumber(b:sub(i, i), 16)))
  end
  return table.concat(out)
end

math.randomseed((os.epoch and os.epoch("utc") or os.clock() * 1000) % 2147483647 + os.getComputerID())

local function randomHex(n)
  local t = {}
  for i = 1, n do t[i] = string.format("%02x", math.random(0, 255)) end
  return table.concat(t)
end
-- ===== FIN CRYPTO =====

-- ---------------------------------------------------------
--  Comptes : accounts[nom en minuscules] = { name, salt, h, admin }
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

local function validName(name)
  return type(name) == "string" and #name >= 3 and #name <= 16 and name:match("^[%w_%-]+$") ~= nil
end

local function adminCount()
  local n = 0
  for _, a in pairs(accounts) do
    if a.admin then n = n + 1 end
  end
  return n
end

-- ---------------------------------------------------------
--  Creation / reinitialisation d'un administrateur (console)
-- ---------------------------------------------------------
local function promptAdmin()
  while true do
    print("Compte administrateur (3-16 car. : lettres, chiffres, _ -)")
    write("Nom : ")
    local name = read()
    write("Mot de passe : ")
    local pw = read("*")
    write("Confirme : ")
    local pw2 = read("*")
    if not validName(name) then
      print("Nom invalide.")
    elseif #pw < MIN_PASSWORD then
      print("Mot de passe trop court (min " .. MIN_PASSWORD .. ").")
    elseif pw ~= pw2 then
      print("Les mots de passe different.")
    else
      local existed = accounts[name:lower()] ~= nil
      local salt = randomHex(16)
      accounts[name:lower()] = { name = name, salt = salt, h = sha256(salt .. pw), admin = true }
      saveAccounts()
      print(existed and "Compte mis a jour (administrateur)." or "Compte administrateur cree.")
      return
    end
  end
end

loadAccounts()

if args[1] == "admin" then
  promptAdmin()
  return
end

if adminCount() == 0 then
  print("Premiere installation : aucun administrateur.")
  promptAdmin()
end

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
--  Etat : connexions en cours et sessions ouvertes
--  sessions[id de l'ordinateur] = { user, sk (cle de session), c (compteur) }
-- ---------------------------------------------------------
local pending, sessions = {}, {}

local function log(text)
  print(textutils.formatTime(os.time(), true) .. " " .. text)
end

local function reply(id, t) rednet.send(id, t, AUTH) end
local function toChat(id, t) rednet.send(id, t, CHAT) end

-- Reponse a une requete signee : renvoie le meme compteur pour que le
-- client reconnaisse la reponse qui lui correspond.
local function answer(id, m, t)
  if type(m.c) == "number" then t.c = m.c end
  reply(id, t)
end

local function broadcast(t)
  for id in pairs(sessions) do toChat(id, t) end
end

local function findSession(name)
  for id, s in pairs(sessions) do
    if s.user:lower() == name:lower() then return id, s end
  end
end

-- Ferme les sessions d'un compte (suppression, mot de passe reinitialise)
local function kickUser(key, exceptId)
  for id, s in pairs(sessions) do
    if s.user:lower() == key and id ~= exceptId then
      toChat(id, { t = "kick" })
      sessions[id] = nil
    end
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

local function authed(id, m)
  local s = verified(id, m)
  if not s then
    answer(id, m, { t = "err", x = "Session invalide, reconnecte-toi" })
  end
  return s
end

local function adminOnly(id, m)
  local s = authed(id, m)
  if not s then return nil end
  local acc = accounts[s.user:lower()]
  if not (acc and acc.admin) then
    answer(id, m, { t = "err", x = "Reserve aux administrateurs" })
    return nil
  end
  return s
end

-- Les empreintes de mot de passe envoyees apres la connexion sont
-- chiffrees avec la cle de session (XOR) : elles ne circulent pas en clair.
local function decryptHash(s, m, enc)
  if type(enc) ~= "string" or #enc ~= 64 or not enc:match("^%x+$") then return nil end
  return xorHex(enc, hmac(s.sk, "enc|" .. m.c))
end

-- ---------------------------------------------------------
--  Requetes non signees : creation de compte et connexion
-- ---------------------------------------------------------
local function onRegister(id, m)
  local user = m.u
  if not validName(user) then
    return reply(id, { t = "err", x = "Nom invalide (3-16 car. : lettres, chiffres, _ -)" })
  end
  if type(m.salt) ~= "string" or not m.salt:match("^%x+$") or #m.salt > 64
    or type(m.h) ~= "string" or not m.h:match("^%x+$") or #m.h ~= 64 then
    return reply(id, { t = "err", x = "Requete invalide" })
  end
  if accounts[user:lower()] then
    return reply(id, { t = "err", x = "Ce nom est deja pris" })
  end
  accounts[user:lower()] = { name = user, salt = m.salt, h = m.h, admin = false }
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
  local acc = p and accounts[p.key]
  if not acc or type(m.p) ~= "string" then
    return reply(id, { t = "err", x = "Identifiants incorrects" })
  end
  local sk = hmac(acc.h, p.n)
  if hmac(sk, "login") ~= m.p then
    log("Echec de connexion : " .. acc.name)
    return reply(id, { t = "err", x = "Identifiants incorrects" })
  end
  sessions[id] = { user = acc.name, sk = sk, c = 0 }
  log(acc.name .. " connecte (ordinateur " .. id .. ")")
  reply(id, { t = "ok", user = acc.name, admin = acc.admin == true })
  broadcast({ t = "sys", x = acc.name .. " s'est connecte" })
end

-- ---------------------------------------------------------
--  Requetes signees
-- ---------------------------------------------------------
local function onMsg(id, m)
  local s = authed(id, m)
  if not s then return end
  local text = (m.x or ""):sub(1, 200)
  if text == "" then return answer(id, m, { t = "ok" }) end
  if m.to then
    local tid, ts = findSession(m.to)
    if not tid then
      return answer(id, m, { t = "err", x = m.to .. " n'est pas connecte" })
    end
    local pkt = { t = "chat", from = s.user, to = ts.user, x = text }
    toChat(tid, pkt)
    if tid ~= id then toChat(id, pkt) end
  else
    broadcast({ t = "chat", from = s.user, x = text })
  end
  answer(id, m, { t = "ok" })
end

local function onBye(id, m)
  local s = authed(id, m)
  if not s then return end
  sessions[id] = nil
  log(s.user .. " deconnecte")
  answer(id, m, { t = "ok" })
  broadcast({ t = "sys", x = s.user .. " s'est deconnecte" })
end

-- Changer son propre mot de passe : x = "sel:empreinte chiffree"
local function onPasswd(id, m)
  local s = authed(id, m)
  if not s then return end
  local salt, enc = tostring(m.x):match("^(%x+):(%x+)$")
  local h = salt and #salt <= 64 and decryptHash(s, m, enc)
  if not h then return answer(id, m, { t = "err", x = "Requete invalide" }) end
  local acc = accounts[s.user:lower()]
  acc.salt, acc.h = salt, h
  saveAccounts()
  log("Mot de passe modifie : " .. acc.name)
  answer(id, m, { t = "ok" })
end

local function onUsers(id, m)
  if not adminOnly(id, m) then return end
  local list = {}
  for _, a in pairs(accounts) do
    list[#list + 1] = { name = a.name, admin = a.admin == true }
  end
  table.sort(list, function(a, b) return a.name:lower() < b.name:lower() end)
  answer(id, m, { t = "users", list = list })
end

-- Creer un compte (admin) : x = "nom:sel:empreinte chiffree:admin(0/1)"
local function onAddUser(id, m)
  local s = adminOnly(id, m)
  if not s then return end
  local name, salt, enc, flag = tostring(m.x):match("^([^:]*):(%x+):(%x+):([01])$")
  local h = name and #salt <= 64 and decryptHash(s, m, enc)
  if not validName(name) or not h then
    return answer(id, m, { t = "err", x = "Requete invalide (nom : 3-16 car. : lettres, chiffres, _ -)" })
  end
  if accounts[name:lower()] then
    return answer(id, m, { t = "err", x = "Ce nom est deja pris" })
  end
  accounts[name:lower()] = { name = name, salt = salt, h = h, admin = flag == "1" }
  saveAccounts()
  log(s.user .. " a cree le compte " .. name .. (flag == "1" and " (admin)" or ""))
  answer(id, m, { t = "ok" })
end

local function onDelUser(id, m)
  local s = adminOnly(id, m)
  if not s then return end
  local key = type(m.to) == "string" and m.to:lower() or ""
  local target = accounts[key]
  if not target then return answer(id, m, { t = "err", x = "Utilisateur inconnu" }) end
  if key == s.user:lower() then
    return answer(id, m, { t = "err", x = "Tu ne peux pas supprimer ton propre compte" })
  end
  if target.admin and adminCount() <= 1 then
    return answer(id, m, { t = "err", x = "Impossible : dernier administrateur" })
  end
  accounts[key] = nil
  saveAccounts()
  kickUser(key)
  log(s.user .. " a supprime le compte " .. target.name)
  answer(id, m, { t = "ok" })
end

-- Changer le role : to = nom, x = "1" (admin) ou "0"
local function onSetAdmin(id, m)
  local s = adminOnly(id, m)
  if not s then return end
  local key = type(m.to) == "string" and m.to:lower() or ""
  local target = accounts[key]
  if not target then return answer(id, m, { t = "err", x = "Utilisateur inconnu" }) end
  if m.x ~= "0" and m.x ~= "1" then return answer(id, m, { t = "err", x = "Requete invalide" }) end
  if m.x == "0" and target.admin and adminCount() <= 1 then
    return answer(id, m, { t = "err", x = "Impossible : dernier administrateur" })
  end
  target.admin = m.x == "1"
  saveAccounts()
  log(s.user .. " : " .. target.name .. (target.admin and " devient admin" or " n'est plus admin"))
  answer(id, m, { t = "ok" })
end

-- Reinitialiser le mot de passe d'un autre compte : to = nom, x = "sel:empreinte chiffree"
local function onResetPw(id, m)
  local s = adminOnly(id, m)
  if not s then return end
  local key = type(m.to) == "string" and m.to:lower() or ""
  local target = accounts[key]
  if not target then return answer(id, m, { t = "err", x = "Utilisateur inconnu" }) end
  local salt, enc = tostring(m.x):match("^(%x+):(%x+)$")
  local h = salt and #salt <= 64 and decryptHash(s, m, enc)
  if not h then return answer(id, m, { t = "err", x = "Requete invalide" }) end
  target.salt, target.h = salt, h
  saveAccounts()
  kickUser(key, id)
  log(s.user .. " a reinitialise le mot de passe de " .. target.name)
  answer(id, m, { t = "ok" })
end

local handlers = {
  reg = onRegister, hello = onHello, login = onLogin,
  msg = onMsg, bye = onBye, passwd = onPasswd,
  users = onUsers, adduser = onAddUser, deluser = onDelUser,
  setadmin = onSetAdmin, resetpw = onResetPw,
}

log("Serveur pret (nom '" .. HOSTNAME .. "', ordinateur " .. os.getComputerID() .. ")")

while true do
  local id, m = rednet.receive(AUTH)
  if type(m) == "table" and handlers[m.t] then
    local ok, err = pcall(handlers[m.t], id, m)
    if not ok then log("Erreur : " .. tostring(err)) end
  end
end