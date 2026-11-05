-- =========================================================
--  MiniOS 0.4 - un petit systeme a sessions pour CC: Tweaked
--  (ordinateur avance, avec ecran couleur)
--
--  Usage : minios            (pour tester)
--          renomme-le en "startup" pour le lancer au demarrage
--
--  - les comptes sont COMMUNS a tous les ordinateurs MiniOS : ils
--    vivent sur l'ordinateur serveur (minios_server.lua), qui doit
--    etre allume et a portee radio pour qu'on puisse se connecter
--  - ecran de connexion avec creation de compte libre
--  - dossier personnel et theme par utilisateur (propres a chaque
--    ordinateur), verrouillage, verrouillage automatique
--  - messagerie : tes messages sont recus pendant toute la session
--
--  Ce n'est PAS une vraie securite : CC n'a pas de systeme de
--  droits, et quelqu'un qui a acces aux fichiers d'un ordinateur
--  (ou du serveur) peut tout contourner.
--  NB : pas d'accents dans les textes (l'ecran de CC ne les
--  affiche pas correctement avec de l'UTF-8).
-- =========================================================

local NAME, VERSION = "MiniOS", "0.4"
local AUTH, CHAT = "minios_auth", "minios_chat"
local SERVER_NAME = "minios-server"
local HOME_ROOT = "/home"
local MIN_PASSWORD = 4
local AUTOLOCK = 300  -- secondes d'inactivite avant verrouillage (0 = jamais)
local KIOSK = true    -- true : Ctrl+T est ignore (on ne peut pas s'echapper
                      --        sans mot de passe). Mets false pour developper.

if not term.isColor() then
  print(NAME .. " demande un ordinateur avance (couleur).")
  return
end

-- Theme par defaut (chaque utilisateur a le sien dans son dossier)
local defaultTheme = {
  bg = colors.blue,       -- fond du bureau
  bar = colors.gray,      -- barres du haut et du bas
  accent = colors.orange, -- couleur d'accent
  text = colors.white,
  barText = colors.white,
}
local theme = {}
local function resetTheme()
  for k, v in pairs(defaultTheme) do theme[k] = v end
end
resetTheme()

local w, h = term.getSize()

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

-- =========================================================
--  Outils d'affichage et d'entree
-- =========================================================

local function writeAt(x, y, text, fg, bg)
  term.setCursorPos(x, y)
  term.setTextColor(fg or colors.white)
  term.setBackgroundColor(bg or colors.black)
  term.write(text)
end

local function clear(bg, fg)
  term.setBackgroundColor(bg or colors.black)
  term.setTextColor(fg or colors.white)
  term.clear()
  term.setCursorPos(1, 1)
end

local function bar(y, text, fg, bg)
  term.setBackgroundColor(bg)
  term.setCursorPos(1, y)
  term.clearLine()
  writeAt(1, y, text, fg, bg)
end

local function centered(y, text, fg, bg)
  writeAt(math.floor((w - #text) / 2) + 1, y, text, fg, bg)
end

-- =========================================================
--  Etat de la session (session = nil quand personne n'est connecte)
--  session = { user, admin, serverId, sk, salt, h, counter, home }
-- =========================================================

local session = nil
local pendingAction = nil
local kicked = false                     -- le serveur a ferme notre session
local chatLog, unread, chatOpen = {}, 0, false

local function addChatLine(text)
  while #text > 0 do
    chatLog[#chatLog + 1] = text:sub(1, w)
    text = text:sub(w + 1)
  end
  while #chatLog > 200 do table.remove(chatLog, 1) end
end

-- Paquets envoyes par le serveur : messages, annonces, fermeture de session
local function onChatPacket(b)
  if b.t == "chat" and type(b.from) == "string" and type(b.x) == "string" then
    local line
    if b.to then
      if session and b.from == session.user then
        line = "[MP a " .. tostring(b.to) .. "] " .. b.x
      else
        line = "[MP de " .. b.from .. "] " .. b.x
      end
    else
      line = b.from .. ": " .. b.x
    end
    addChatLine(line)
    if not chatOpen then unread = unread + 1 end
  elseif b.t == "sys" and type(b.x) == "string" then
    addChatLine("* " .. b.x)
  elseif b.t == "kick" then
    kicked = true
  end
end

-- os.pullEvent qui ignore Ctrl+T en mode KIOSK et qui recoit les messages
-- du serveur ou que l'on soit dans MiniOS (la messagerie reste active)
local function pullEvent(filter)
  while true do
    local ev, a, b, c, d = os.pullEventRaw(filter)
    if ev == "terminate" then
      if not KIOSK then error("Terminated", 0) end
    else
      if ev == "rednet_message" and session and a == session.serverId
        and c == CHAT and type(b) == "table" then
        onChatPacket(b)
      end
      return ev, a, b, c, d
    end
  end
end

local function pause(seconds)
  local timer = os.startTimer(seconds)
  repeat
    local ev, id = pullEvent()
  until ev == "timer" and id == timer
end

local function waitKey()
  pullEvent("key")
end

-- Saisie d'une ligne (mask = "*" pour un mot de passe). En mode KIOSK,
-- Ctrl+T ne ferme pas la saisie, elle recommence.
local function ask(label, mask, x, y)
  local cx, cy = term.getCursorPos()
  x, y = x or cx, y or cy
  while true do
    term.setBackgroundColor(colors.black)
    term.setTextColor(colors.white)
    term.setCursorPos(x, y)
    term.clearLine()
    term.write(label)
    local ok, v = pcall(read, mask)
    if ok then return v end
    if not KIOSK or not tostring(v):find("Terminated") then error(v, 0) end
  end
end

local function notice(text)
  term.setBackgroundColor(colors.black)
  term.setTextColor(colors.white)
  print()
  print(text)
  print("Appuie sur une touche...")
  waitKey()
end

-- =========================================================
--  Reseau : serveur de comptes, connexion, requetes signees
-- =========================================================

local function validName(name)
  return type(name) == "string" and #name >= 3 and #name <= 16 and name:match("^[%w_%-]+$") ~= nil
end

local function openModem()
  for _, name in ipairs(peripheral.getNames()) do
    if peripheral.getType(name) == "modem" then
      if not rednet.isOpen(name) then rednet.open(name) end
      return true
    end
  end
  return false
end

local function findServer()
  if not openModem() then return nil, "Aucun modem detecte" end
  local id = rednet.lookup(AUTH, SERVER_NAME)
  if not id then return nil, "Serveur MiniOS introuvable" end
  return id
end

-- Envoie une requete au serveur et attend sa reponse (nil si rien).
-- expectC : compteur de la requete, pour ne prendre que la bonne reponse.
local function request(serverId, tbl, timeout, expectC)
  rednet.send(serverId, tbl, AUTH)
  local deadline = os.startTimer(timeout or 3)
  while true do
    local ev, a, b, c = pullEvent()
    if ev == "rednet_message" and a == serverId and c == AUTH and type(b) == "table"
      and (expectC == nil or b.c == expectC) then
      os.cancelTimer(deadline)
      return b
    elseif ev == "timer" and a == deadline then
      return nil
    end
  end
end

local function register(serverId, user, pw)
  local salt = randomHex(16)
  local r = request(serverId, { t = "reg", u = user, salt = salt, h = sha256(salt .. pw) })
  if not r then return false, "Le serveur ne repond pas" end
  if r.t == "ok" then return true end
  return false, r.x or "Erreur"
end

-- Connexion par defi : le mot de passe ne circule jamais sur la radio.
-- Renvoie une session, ou nil + message d'erreur.
local function login(serverId, user, pw)
  local r = request(serverId, { t = "hello", u = user })
  if not r then return nil, "Le serveur ne repond pas" end
  if r.t ~= "chal" then return nil, r.x or "Erreur" end
  if type(r.salt) ~= "string" or type(r.n) ~= "string" then return nil, "Reponse invalide" end
  local h = sha256(r.salt .. pw)
  local sk = hmac(h, r.n)
  local r2 = request(serverId, { t = "login", p = hmac(sk, "login") })
  if not r2 then return nil, "Le serveur ne repond pas" end
  if r2.t ~= "ok" or type(r2.user) ~= "string" then return nil, r2.x or "Erreur" end
  return { user = r2.user, admin = r2.admin == true, serverId = serverId,
           sk = sk, salt = r.salt, h = h, counter = 0 }
end

-- Requete signee avec la cle de session et numerotee (anti-rejeu).
-- x peut etre une fonction(compteur) -> texte, pour chiffrer avec le bon compteur.
-- Renvoie la reponse du serveur, ou nil + message d'erreur.
local function call(kind, to, x, timeout)
  session.counter = session.counter + 1
  local c = session.counter
  if type(x) == "function" then x = x(c) end
  local sig = hmac(session.sk, table.concat({ c, kind, to or "", x or "" }, "|"))
  local r = request(session.serverId, { t = kind, c = c, to = to, x = x, s = sig }, timeout, c)
  if not r then return nil, "Le serveur ne repond pas" end
  if r.t == "err" then return nil, r.x or "Erreur" end
  return r
end

-- =========================================================
--  Reglages sauvegardes dans le dossier de l'utilisateur
-- =========================================================

local function saveSettings()
  local f = fs.open(fs.combine(session.home, ".settings"), "w")
  if f then
    f.write(textutils.serialize(theme))
    f.close()
  end
end

local function loadSettings()
  resetTheme()
  local path = fs.combine(session.home, ".settings")
  if not fs.exists(path) then return end
  local f = fs.open(path, "r")
  if not f then return end
  local data = textutils.unserialize(f.readAll())
  f.close()
  if type(data) == "table" then
    for k, v in pairs(data) do
      if theme[k] ~= nil then theme[k] = v end
    end
  end
end

-- =========================================================
--  Ecrans : connexion / creation de compte, verrouillage
-- =========================================================

-- Une tentative : choice "1" = connexion, "2" = creation de compte
local function tryAuth(choice)
  clear(colors.black, colors.white)
  local mid = math.floor(h / 2)
  bar(1, " " .. NAME .. " " .. VERSION, defaultTheme.barText, defaultTheme.bar)
  centered(mid - 3, choice == "1" and "Connexion" or "Creation de compte",
    defaultTheme.accent, colors.black)

  local serverId, err = findServer()
  if not serverId then return nil, err end

  local name = ask("Utilisateur : ", nil, 2, mid - 1)
  local pw = ask("Mot de passe : ", "*", 2, mid)
  if choice == "2" then
    if ask("Confirme : ", "*", 2, mid + 1) ~= pw then
      return nil, "Les mots de passe different"
    end
    if not validName(name) then
      return nil, "Nom invalide (3-16 car. : lettres, chiffres, _ -)"
    end
    if #pw < MIN_PASSWORD then
      return nil, "Mot de passe trop court (min " .. MIN_PASSWORD .. ")"
    end
    local ok, e = register(serverId, name, pw)
    if not ok then return nil, e end
  end
  return login(serverId, name, pw)
end

local function loginScreen()
  local fails = 0
  while true do
    clear(colors.black, colors.white)
    bar(1, " " .. NAME .. " " .. VERSION, defaultTheme.barText, defaultTheme.bar)
    local mid = math.floor(h / 2)
    centered(mid - 3, "Bienvenue", defaultTheme.accent, colors.black)
    centered(mid - 1, "[1] Connexion", colors.white, colors.black)
    centered(mid + 1, "[2] Creer un compte", colors.white, colors.black)

    local choice
    while not choice do
      local ev, a, b, c = pullEvent()
      if ev == "char" and (a == "1" or a == "2") then
        choice = a
      elseif ev == "mouse_click" then
        if c == mid - 1 then choice = "1" elseif c == mid + 1 then choice = "2" end
      end
    end

    local s, err = tryAuth(choice)
    if s then return s end
    if err == "Identifiants incorrects" then fails = fails + 1 end
    centered(mid + 3, err or "Erreur", colors.red, colors.black)
    pause(math.max(2, math.min(1 + fails, 8)))
  end
end

-- Verrouillage : le mot de passe est verifie localement (pas besoin du serveur)
local function lockScreen()
  local fails = 0
  while true do
    clear(colors.black, colors.white)
    local mid = math.floor(h / 2)
    centered(mid - 3, "Session verrouillee", theme.accent, colors.black)
    centered(mid - 2, session.user, colors.white, colors.black)
    local pw = ask("Mot de passe : ", "*", 2, mid)
    if sha256(session.salt .. pw) == session.h then return end
    fails = fails + 1
    centered(mid + 2, "Mot de passe incorrect", colors.red, colors.black)
    pause(math.max(2, math.min(1 + fails, 8)))
  end
end

-- =========================================================
--  Applications : chaque appli est une fonction sans argument
-- =========================================================

-- Terminal (administrateurs) : un shell classique, "exit" pour revenir
local function terminalApp()
  clear(colors.black, colors.white)
  print(NAME .. " - tape 'exit' pour revenir au bureau")
  shell.setDir(session.home)
  shell.run("shell")
end

-- Fichiers : un utilisateur reste dans son dossier, un admin voit tout
local function filesApp()
  local root = session.admin and "" or session.home
  local path, sel, scroll = session.home, 1, 0
  while true do
    local list = fs.list(path)
    table.sort(list, function(a, b)
      local da, db = fs.isDir(fs.combine(path, a)), fs.isDir(fs.combine(path, b))
      if da ~= db then return da end
      return a:lower() < b:lower()
    end)

    if sel > #list then sel = math.max(#list, 1) end
    local rows = h - 2
    if sel <= scroll then scroll = sel - 1 end
    if sel > scroll + rows then scroll = sel - rows end

    clear(colors.black, colors.white)
    bar(1, " /" .. path, theme.barText, theme.bar)
    for i = 1, rows do
      local name = list[scroll + i]
      if not name then break end
      local isDir = fs.isDir(fs.combine(path, name))
      local selected = (scroll + i == sel)
      local line = " " .. name .. (isDir and "/" or "")
      line = line .. string.rep(" ", w - #line)
      writeAt(1, 1 + i, line,
        selected and colors.black or (isDir and colors.yellow or colors.white),
        selected and theme.accent or colors.black)
    end
    bar(h, " Entree:ouvrir Retour:parent Q:quitter", theme.barText, theme.bar)

    local _, key = pullEvent("key")
    if key == keys.up and sel > 1 then
      sel = sel - 1
    elseif key == keys.down and sel < #list then
      sel = sel + 1
    elseif key == keys.backspace and path ~= root then
      path = fs.getDir(path)
      sel, scroll = 1, 0
    elseif key == keys.enter and list[sel] then
      local full = fs.combine(path, list[sel])
      if fs.isDir(full) then
        path = full
        sel, scroll = 1, 0
      else
        shell.run("edit", full)
      end
    elseif key == keys.q then
      return
    end
  end
end

-- Bloc-notes : notes.txt dans le dossier personnel
local function notesApp()
  shell.run("edit", fs.combine(session.home, "notes.txt"))
end

-- Horloge : heure du jeu + heure reelle du serveur
local function clockApp()
  while true do
    clear(colors.black, colors.white)
    local mid = math.floor(h / 2)
    centered(mid - 2, "Heure du jeu", colors.lightGray, colors.black)
    centered(mid - 1, textutils.formatTime(os.time(), true), theme.accent, colors.black)
    centered(mid + 1, "Jour " .. os.day(), colors.white, colors.black)
    centered(mid + 3, "Heure reelle (serveur)", colors.lightGray, colors.black)
    centered(mid + 4, os.date("%H:%M:%S"), theme.accent, colors.black)
    centered(h, "Une touche pour quitter", colors.gray, colors.black)

    local timer = os.startTimer(1)
    repeat
      local ev, a = pullEvent()
      if ev == "key" or ev == "mouse_click" then return end
    until ev == "timer" and a == timer
  end
end

-- ---------------------------------------------------------
--  Messagerie : les messages arrivent pendant toute la session
--  (journal chatLog, compteur "Msg:n" sur le bureau) ; l'appli sert
--  a les lire et a en envoyer.
-- ---------------------------------------------------------

local function chatApp()
  local input = ""

  local function draw()
    clear(colors.black, colors.white)
    bar(1, " Chat - " .. session.user .. "  (ID " .. os.getComputerID() .. ")", theme.barText, theme.bar)
    local rows = h - 2
    local first = math.max(1, #chatLog - rows + 1)
    for i = first, #chatLog do
      writeAt(1, 2 + i - first, chatLog[i], colors.white, colors.black)
    end
    writeAt(1, h, "> " .. input:sub(-(w - 3)) .. "_", theme.accent, colors.black)
  end

  local function sendMsg(to, text)
    local r, err = call("msg", to, text)
    if not r then addChatLine("! " .. tostring(err)) end
  end

  local function run()
    if #chatLog == 0 then addChatLine("/w nom message = prive, /quit = sortir") end
    while true do
      draw()
      local ev, a = pullEvent()
      if ev == "char" then
        input = input .. a
      elseif ev == "key" then
        if a == keys.backspace then
          input = input:sub(1, -2)
        elseif a == keys.enter then
          local text = input
          input = ""
          if text == "/quit" then
            return
          elseif text:sub(1, 3) == "/w " then
            local to, msg = text:match("^/w%s+(%S+)%s+(.+)$")
            if to then sendMsg(to, msg) else addChatLine("Usage : /w nom message") end
          elseif text ~= "" then
            sendMsg(nil, text)
          end
        end
      end
      -- (les messages recus ont deja ete ajoutes au journal par pullEvent)
    end
  end

  chatOpen, unread = true, 0
  local ok, err = pcall(run)
  chatOpen = false
  if not ok then error(err, 0) end
end

-- ---------------------------------------------------------
--  Reglages : couleurs du theme (propres a chaque utilisateur)
-- ---------------------------------------------------------

local palette = {
  colors.blue, colors.cyan, colors.green, colors.lime, colors.orange,
  colors.red, colors.purple, colors.magenta, colors.brown, colors.gray,
  colors.black,
}

local function nextColor(current, dir)
  local idx = 1
  for i, c in ipairs(palette) do
    if c == current then idx = i end
  end
  idx = (idx - 1 + dir) % #palette + 1
  return palette[idx]
end

local function settingsApp()
  local items = {
    { label = "Fond du bureau", key = "bg" },
    { label = "Barres",         key = "bar" },
    { label = "Accent",         key = "accent" },
  }
  local sel = 1
  while true do
    clear(colors.black, colors.white)
    bar(1, " Reglages", theme.barText, theme.bar)
    for i, item in ipairs(items) do
      local y = 1 + i * 2
      writeAt(2, y, (i == sel and "> " or "  ") .. item.label, colors.white, colors.black)
      writeAt(w - 5, y, "    ", colors.white, theme[item.key])
    end
    bar(h, " Fleches:changer  Q:retour", theme.barText, theme.bar)

    local _, key = pullEvent("key")
    if key == keys.up and sel > 1 then
      sel = sel - 1
    elseif key == keys.down and sel < #items then
      sel = sel + 1
    elseif key == keys.left then
      theme[items[sel].key] = nextColor(theme[items[sel].key], -1)
    elseif key == keys.right then
      theme[items[sel].key] = nextColor(theme[items[sel].key], 1)
    elseif key == keys.q then
      saveSettings()
      return
    end
  end
end

-- ---------------------------------------------------------
--  Comptes : mot de passe pour tous, gestion pour les admins.
--  Tout passe par le serveur (comptes communs a tous les ordinateurs).
-- ---------------------------------------------------------

-- Les empreintes envoyees au serveur sont chiffrees avec la cle de session
local function protectHash(c, hash)
  return xorHex(hash, hmac(session.sk, "enc|" .. c))
end

local function newCredentials(pw)
  local salt = randomHex(16)
  return salt, sha256(salt .. pw)
end

local function readNewPassword()
  local p1 = ask("Nouveau mot de passe : ", "*")
  local p2 = ask("Confirme : ", "*")
  if p1 ~= p2 then return nil, "Les mots de passe different" end
  if #p1 < MIN_PASSWORD then return nil, "Trop court (min " .. MIN_PASSWORD .. ")" end
  return p1
end

local function changeOwnPassword()
  local old = ask("Mot de passe actuel : ", "*")
  if sha256(session.salt .. old) ~= session.h then return notice("Mot de passe incorrect") end
  local pw, err = readNewPassword()
  if not pw then return notice(err) end
  local salt, hash = newCredentials(pw)
  local r, e = call("passwd", nil, function(c) return salt .. ":" .. protectHash(c, hash) end)
  if not r then return notice(e) end
  session.salt, session.h = salt, hash
  notice("Mot de passe modifie.")
end

local function listUsers()
  local r, e = call("users")
  if not r or type(r.list) ~= "table" then return notice(e or "Reponse invalide") end
  clear(colors.black, colors.white)
  bar(1, " Utilisateurs", theme.barText, theme.bar)
  for i, u in ipairs(r.list) do
    if 2 + i < h then
      writeAt(2, 2 + i, tostring(u.name) .. (u.admin and "  [admin]" or ""), colors.white, colors.black)
    end
  end
  writeAt(1, h, "Une touche pour revenir", colors.gray, colors.black)
  waitKey()
end

local function createUser()
  local name = ask("Nom : ")
  local pw, err = readNewPassword()
  if not pw then return notice(err) end
  local admin = ask("Administrateur ? (o/n) : "):lower() == "o"
  local salt, hash = newCredentials(pw)
  local r, e = call("adduser", nil, function(c)
    return table.concat({ name, salt, protectHash(c, hash), admin and "1" or "0" }, ":")
  end)
  notice(r and ("Utilisateur " .. name .. " cree.") or e)
end

local function deleteUser()
  local name = ask("Nom a supprimer : ")
  if ask("Supprimer " .. name .. " ? (o/n) : "):lower() ~= "o" then return end
  local r, e = call("deluser", name)
  notice(r and "Utilisateur supprime." or e)
end

local function resetPassword()
  local name = ask("Nom : ")
  local pw, err = readNewPassword()
  if not pw then return notice(err) end
  local salt, hash = newCredentials(pw)
  local r, e = call("resetpw", name, function(c) return salt .. ":" .. protectHash(c, hash) end)
  notice(r and "Mot de passe reinitialise." or e)
end

local function changeRole()
  local name = ask("Nom : ")
  local admin = ask("Administrateur ? (o/n) : "):lower() == "o"
  local r, e = call("setadmin", name, admin and "1" or "0")
  notice(r and "Role modifie." or e)
end

local function accountsApp()
  while true do
    clear(colors.black, colors.white)
    bar(1, " Comptes - " .. session.user, theme.barText, theme.bar)
    term.setBackgroundColor(colors.black)
    term.setTextColor(colors.white)
    term.setCursorPos(1, 3)
    print("1) Changer mon mot de passe")
    if session.admin then
      print("2) Liste des utilisateurs")
      print("3) Creer un utilisateur")
      print("4) Supprimer un utilisateur")
      print("5) Reinitialiser un mot de passe")
      print("6) Changer le role (admin/non)")
    end
    print("Q) Retour")
    print()
    local choice = ask("> "):lower()
    if choice == "q" then return end
    if choice == "1" then
      changeOwnPassword()
    elseif session.admin and choice == "2" then
      listUsers()
    elseif session.admin and choice == "3" then
      createUser()
    elseif session.admin and choice == "4" then
      deleteUser()
    elseif session.admin and choice == "5" then
      resetPassword()
    elseif session.admin and choice == "6" then
      changeRole()
    end
  end
end

-- ---------------------------------------------------------
--  Menu Session : verrouiller, deconnexion, alimentation
-- ---------------------------------------------------------

local function sessionApp()
  while true do
    clear(colors.black, colors.white)
    bar(1, " Session - " .. session.user, theme.barText, theme.bar)
    term.setBackgroundColor(colors.black)
    term.setTextColor(colors.white)
    term.setCursorPos(1, 3)
    print("1) Verrouiller")
    print("2) Se deconnecter")
    print("3) Redemarrer")
    print("4) Eteindre")
    if session.admin then print("5) Quitter vers CraftOS") end
    print("Q) Retour")
    print()
    local choice = ask("> "):lower()
    if choice == "1" then
      lockScreen()
      return
    elseif choice == "2" then
      pendingAction = "logout"
      return
    elseif choice == "3" then
      call("bye", nil, nil, 1)
      os.reboot()
      return
    elseif choice == "4" then
      call("bye", nil, nil, 1)
      os.shutdown()
      return
    elseif choice == "5" and session.admin then
      pendingAction = "exit"
      return
    elseif choice == "q" then
      return
    end
  end
end

-- =========================================================
--  Registre des applications : ajoutes-en une ici !
--  admin = true : visible seulement pour les administrateurs
-- =========================================================

local apps = {
  { name = "Terminal",   run = terminalApp, admin = true },
  { name = "Fichiers",   run = filesApp },
  { name = "Bloc-notes", run = notesApp },
  { name = "Horloge",    run = clockApp },
  { name = "Messagerie", run = chatApp },
  { name = "Reglages",   run = settingsApp },
  { name = "Comptes",    run = accountsApp },
  { name = "Session",    run = sessionApp },
}

local menu = {}

local function buildMenu()
  menu = {}
  for _, app in ipairs(apps) do
    if not app.admin or session.admin then menu[#menu + 1] = app end
  end
end

-- =========================================================
--  Demarrage et bureau
-- =========================================================

local function boot()
  clear(colors.black, colors.white)
  local mid = math.floor(h / 2)
  centered(mid - 1, NAME, defaultTheme.accent, colors.black)
  centered(mid, "v" .. VERSION, colors.lightGray, colors.black)
  local bw = math.min(20, w - 4)
  local x = math.floor((w - bw) / 2) + 1
  for i = 1, bw do
    writeAt(x + i - 1, mid + 2, " ", colors.white, defaultTheme.accent)
    sleep(0.05)
  end
end

local function showError(name, err)
  clear(colors.black, colors.red)
  print(name .. " a plante :")
  print()
  print(tostring(err))
  print()
  print("Appuie sur une touche...")
  waitKey()
end

local function launch(i)
  local app = menu[i]
  clear(colors.black, colors.white)
  local ok, err = pcall(app.run)
  -- Ctrl+T dans une appli (mode developpement) = retour au bureau
  if not ok and not tostring(err):find("Terminated") then
    showError(app.name, err)
  end
end

local function appRow(i)
  local spacing = (3 + (#menu - 1) * 2 <= h - 2) and 2 or 1
  return 3 + (i - 1) * spacing
end

local function appAt(y)
  for i = 1, #menu do
    if appRow(i) == y then return i end
  end
end

local function drawClock()
  local t = string.format(" %5s ", textutils.formatTime(os.time(), true))
  writeAt(w - #t + 1, 1, t, theme.barText, theme.bar)
end

-- Dessine le bureau, renvoie le nombre de messages non lus affiche
local function drawDesktop()
  clear(theme.bg, theme.text)
  bar(1, " " .. NAME .. "  " .. session.user .. (session.admin and " [admin]" or ""),
    theme.barText, theme.bar)
  drawClock()
  if unread > 0 then
    local m = " Msg:" .. unread .. " "
    writeAt(w - 7 - #m + 1, 1, m, colors.black, theme.accent)
  end
  for i, app in ipairs(menu) do
    local y = appRow(i)
    writeAt(3, y, "[" .. i .. "]", theme.accent, theme.bg)
    writeAt(7, y, app.name, theme.text, theme.bg)
  end
  bar(h, " Clic ou touche 1-" .. #menu, theme.barText, theme.bar)
  return unread
end

-- Renvoie "logout" ou "exit"
local function desktop()
  local lastActivity = os.clock()
  while true do
    local shownUnread = drawDesktop()
    local timer = os.startTimer(1)
    local redraw = false
    while not redraw do
      local ev, a, b, c = pullEvent()
      local i = nil
      if kicked then return "logout" end
      if ev == "timer" and a == timer then
        drawClock()
        timer = os.startTimer(1)
        if AUTOLOCK > 0 and os.clock() - lastActivity > AUTOLOCK then
          lockScreen()
          lastActivity = os.clock()
          redraw = true
        end
      elseif ev == "mouse_click" then
        lastActivity = os.clock()
        i = appAt(c)
      elseif ev == "char" then
        lastActivity = os.clock()
        i = tonumber(a)
        if i and not menu[i] then i = nil end
      elseif ev == "rednet_message" then
        if unread ~= shownUnread then redraw = true end
      elseif ev == "term_resize" then
        w, h = term.getSize()
        redraw = true
      end

      if i then
        launch(i)
        lastActivity = os.clock()
        if kicked then return "logout" end
        if pendingAction then
          local action = pendingAction
          pendingAction = nil
          return action
        end
        redraw = true
      end
    end
  end
end

-- Boucle de sessions : connexion -> bureau -> deconnexion -> connexion...
-- Ne se termine que si un administrateur choisit "Quitter vers CraftOS".
local function sessionLoop()
  while true do
    session = loginScreen()
    session.home = fs.combine(HOME_ROOT, session.user)
    if not fs.exists(session.home) then fs.makeDir(session.home) end
    kicked, unread, chatLog = false, 0, {}
    loadSettings()
    buildMenu()
    local action = desktop()
    local wasKicked = kicked
    if not wasKicked then call("bye", nil, nil, 1) end
    session = nil   -- la cle de session disparait ici
    resetTheme()
    if wasKicked then
      notice("Ta session a ete fermee par le serveur\n(compte modifie ou supprime).")
    end
    if action == "exit" then return end
  end
end

boot()
while true do
  local ok, err = pcall(sessionLoop)
  if ok then break end
  if not KIOSK then error(err, 0) end
  session = nil
  resetTheme()
  showError(NAME, err)
end
clear(colors.black, colors.white)
print(NAME .. " ferme. A bientot !")