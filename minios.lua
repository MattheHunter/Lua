-- =========================================================
-- MiniOS 0.3 : en-tête de présentation du système.
-- Décrit brièvement la version et le type d’ordinateur requis.
--
-- Indique comment lancer MiniOS manuellement ou au démarrage.
-- Précise le rôle des comptes, des mots de passe et des dossiers personnels.
-- Présente les fonctions de connexion, de verrouillage et de messagerie.
--
-- Avertit que les comptes ne fournissent pas une vraie sécurité système.
-- Explique que l’accès aux fichiers permet de contourner les protections.
-- Signale la limitation d’affichage des accents dans ComputerCraft.
-- =========================================================

local NAME, VERSION = "MiniOS", "0.3" -- Définit le nom et la version du système.
local AUTH, CHAT = "minios_auth", "minios_chat" -- Définit les protocoles réseau utilisés.
local DATA_DIR = "/.minios" -- Définit le dossier de données de MiniOS.
local USERS_FILE = DATA_DIR .. "/users.db" -- Construit le chemin de la base des utilisateurs.
local HOME_ROOT = "/home" -- Définit le dossier racine des dossiers personnels.
local MIN_PASSWORD = 4 -- Définit la longueur minimale des mots de passe.
local AUTOLOCK = 300 -- Définit le délai d’inactivité avant verrouillage, en secondes.
-- Explique que KIOSK=true ignore Ctrl+T pour empêcher de quitter sans mot de passe.
-- Explique que KIOSK=false réactive Ctrl+T pour le développement.
local KIOSK = true -- Active le mode kiosque.

if not term.isColor() then -- Vérifie que le terminal prend en charge les couleurs.
  print(NAME .. " demande un ordinateur avance (couleur).") -- Informe que MiniOS exige un ordinateur avancé.
  return -- Arrête le programme si l’écran couleur n’est pas disponible.
end -- Termine la vérification de l’écran couleur.

-- Décrit le thème utilisé par défaut et celui appliqué à chaque utilisateur.
local defaultTheme = { -- Crée la table contenant les couleurs par défaut.
  bg = colors.blue,       -- Définit la couleur de fond du bureau.
  bar = colors.gray,      -- Définit la couleur des barres supérieure et inférieure.
  accent = colors.orange, -- Définit la couleur des éléments mis en évidence.
  text = colors.white, -- Définit la couleur du texte du bureau.
  barText = colors.white, -- Définit la couleur du texte dans les barres.
} -- Termine la définition du thème par défaut.
local theme = {} -- Crée la table du thème actuellement utilisé.
local function resetTheme() -- Déclare la fonction qui réinitialise le thème.
  for k, v in pairs(defaultTheme) do theme[k] = v end -- Copie chaque couleur par défaut dans le thème actif.
end -- Termine la fonction de réinitialisation du thème.
resetTheme() -- Applique le thème par défaut au démarrage.

local w, h = term.getSize() -- Récupère la largeur et la hauteur du terminal.

-- ===== DEBUT CRYPTO (identique dans minios.lua et minios_server.lua) =====
-- Annonce l’implémentation SHA-256 et HMAC-SHA-256 en Lua pur.
local band, bxor, bnot = bit32.band, bit32.bxor, bit32.bnot -- Récupère les opérations binaires nécessaires.
local rshift, rrotate = bit32.rshift, bit32.rrotate -- Récupère les fonctions de décalage et de rotation de bits.

local K = { -- Contient les constantes utilisées par les tours de SHA-256.
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, -- Constantes SHA-256 1 à 8.
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, -- Constantes SHA-256 9 à 16.
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, -- Constantes SHA-256 17 à 24.
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, -- Constantes SHA-256 25 à 32.
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, -- Constantes SHA-256 33 à 40.
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, -- Constantes SHA-256 41 à 48.
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, -- Constantes SHA-256 49 à 56.
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2, -- Constantes SHA-256 57 à 64.
} -- Termine la table des constantes SHA-256.

local function u32(n) -- Déclare une fonction qui encode un nombre sur 32 bits.
  return string.char(band(rshift(n, 24), 255), band(rshift(n, 16), 255), -- Extrait et convertit les deux octets de poids fort.
    band(rshift(n, 8), 255), band(n, 255)) -- Extrait et convertit les deux octets de poids faible.
end -- Termine la fonction d’encodage sur 32 bits.

local function sha256(msg) -- Déclare la fonction qui calcule le hash SHA-256 d’un message.
  local h0, h1, h2, h3 = 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a -- Initialise les quatre premiers états du hash.
  local h4, h5, h6, h7 = 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 -- Initialise les quatre derniers états du hash.
  local len = #msg -- Mémorise la longueur initiale du message en octets.
  msg = msg .. "\128" .. string.rep("\0", (55 - len) % 64) -- Ajoute le bit de fin et le bourrage requis.
    .. u32(math.floor(len * 8 / 4294967296)) .. u32((len * 8) % 4294967296) -- Ajoute la longueur initiale du message en bits.

  for i = 1, #msg, 64 do -- Traite le message par blocs de 64 octets.
    local w = {} -- Crée le tableau des 64 mots du bloc courant.
    for j = 0, 15 do -- Lit les 16 premiers mots de 32 bits du bloc.
      local a, b, c, d = msg:byte(i + j * 4, i + j * 4 + 3) -- Récupère les quatre octets du mot courant.
      w[j] = a * 16777216 + b * 65536 + c * 256 + d -- Assemble ces octets en un nombre de 32 bits.
    end -- Termine la lecture des 16 premiers mots.
    for j = 16, 63 do -- Complète les 48 mots restants du bloc.
      local s0 = bxor(rrotate(w[j - 15], 7), rrotate(w[j - 15], 18), rshift(w[j - 15], 3)) -- Calcule la première fonction sigma du mot.
      local s1 = bxor(rrotate(w[j - 2], 17), rrotate(w[j - 2], 19), rshift(w[j - 2], 10)) -- Calcule la seconde fonction sigma du mot.
      w[j] = (w[j - 16] + s0 + w[j - 7] + s1) % 4294967296 -- Calcule le mot étendu en restant sur 32 bits.
    end -- Termine l’extension des mots du bloc.
    local a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7 -- Copie l’état courant dans les variables de travail.
    for j = 0, 63 do -- Effectue les 64 tours de calcul du bloc.
      local S1 = bxor(rrotate(e, 6), rrotate(e, 11), rrotate(e, 25)) -- Calcule la fonction sigma majuscule sur e.
      local ch = bxor(band(e, f), band(bnot(e), g)) -- Choisit les bits de f ou de g selon les bits de e.
      local t1 = (h + S1 + ch + K[j + 1] + w[j]) % 4294967296 -- Calcule la première somme temporaire du tour.
      local S0 = bxor(rrotate(a, 2), rrotate(a, 13), rrotate(a, 22)) -- Calcule la fonction sigma majuscule sur a.
      local maj = bxor(band(a, b), band(a, c), band(b, c)) -- Calcule la fonction de majorité bit à bit.
      local t2 = (S0 + maj) % 4294967296 -- Calcule la deuxième somme temporaire du tour.
      h, g, f, e = g, f, e, (d + t1) % 4294967296 -- Décale les variables de travail et met à jour e.
      d, c, b, a = c, b, a, (t1 + t2) % 4294967296 -- Décale les autres variables et met à jour a.
    end -- Termine les 64 tours du bloc.
    h0, h1 = (h0 + a) % 4294967296, (h1 + b) % 4294967296 -- Ajoute les deux premiers résultats à l’état du hash.
    h2, h3 = (h2 + c) % 4294967296, (h3 + d) % 4294967296 -- Ajoute les résultats suivants à l’état du hash.
    h4, h5 = (h4 + e) % 4294967296, (h5 + f) % 4294967296 -- Ajoute les résultats suivants à l’état du hash.
    h6, h7 = (h6 + g) % 4294967296, (h7 + h) % 4294967296 -- Ajoute les deux derniers résultats à l’état du hash.
  end -- Termine le traitement de tous les blocs.
  return string.format("%08x%08x%08x%08x%08x%08x%08x%08x", h0, h1, h2, h3, h4, h5, h6, h7) -- Formate les huit états en hash hexadécimal.
end -- Termine la fonction SHA-256.

local function hexToBin(hex) -- Déclare une fonction qui convertit une chaîne hexadécimale en octets.
  return (hex:gsub("%x%x", function(x) return string.char(tonumber(x, 16)) end)) -- Convertit chaque paire hexadécimale en un caractère binaire.
end -- Termine la conversion hexadécimale vers binaire.

local function hmac(key, msg) -- Déclare la fonction qui calcule un HMAC-SHA-256.
  if #key > 64 then key = hexToBin(sha256(key)) end -- Réduit les clés trop longues à la taille du hash.
  key = key .. string.rep("\0", 64 - #key) -- Complète la clé avec des octets nuls jusqu’à 64 octets.
  local ipad, opad = {}, {} -- Crée les tableaux des blocs internes et externes du HMAC.
  for i = 1, 64 do -- Traite chaque octet de la clé complétée.
    local b = key:byte(i) -- Récupère l’octet courant de la clé.
    ipad[i] = string.char(bxor(b, 0x36)) -- Construit l’octet correspondant au bloc interne.
    opad[i] = string.char(bxor(b, 0x5c)) -- Construit l’octet correspondant au bloc externe.
  end -- Termine la construction des deux blocs du HMAC.
  return sha256(table.concat(opad) .. hexToBin(sha256(table.concat(ipad) .. msg))) -- Calcule puis renvoie le HMAC en hexadécimal.
end -- Termine la fonction HMAC.

math.randomseed((os.epoch and os.epoch("utc") or os.clock() * 1000) % 2147483647 + os.getComputerID()) -- Initialise le générateur pseudo-aléatoire avec l’heure et l’identifiant de l’ordinateur.

local function randomHex(n) -- Déclare une fonction qui génère n octets aléatoires en hexadécimal.
  local t = {} -- Crée le tableau qui recevra les octets générés.
  for i = 1, n do t[i] = string.format("%02x", math.random(0, 255)) end -- Génère chaque octet et le formate sur deux caractères hexadécimaux.
  return table.concat(t) -- Assemble les octets pour former une seule chaîne.
end -- Termine la fonction de génération hexadécimale.
-- ===== FIN CRYPTO =====

-- =========================================================
-- Introduit les fonctions communes d’affichage et de saisie.
-- =========================================================

local function writeAt(x, y, text, fg, bg) -- Déclare une fonction qui écrit du texte à une position donnée.
  term.setCursorPos(x, y) -- Place le curseur aux coordonnées indiquées.
  term.setTextColor(fg or colors.white) -- Choisit la couleur du texte, blanche par défaut.
  term.setBackgroundColor(bg or colors.black) -- Choisit la couleur de fond, noire par défaut.
  term.write(text) -- Écrit le texte à partir du curseur.
end -- Termine la fonction d’écriture positionnée.

local function clear(bg, fg) -- Déclare une fonction qui efface l’écran avec les couleurs indiquées.
  term.setBackgroundColor(bg or colors.black) -- Choisit la couleur de fond, noire par défaut.
  term.setTextColor(fg or colors.white) -- Choisit la couleur du texte, blanche par défaut.
  term.clear() -- Efface le contenu du terminal.
  term.setCursorPos(1, 1) -- Replace le curseur dans le coin supérieur gauche.
end -- Termine la fonction d’effacement de l’écran.

local function bar(y, text, fg, bg) -- Déclare une fonction qui affiche une barre sur une ligne.
  term.setBackgroundColor(bg) -- Définit la couleur de fond de la ligne.
  term.setCursorPos(1, y) -- Place le curseur au début de la ligne choisie.
  term.clearLine() -- Efface le contenu actuel de cette ligne.
  writeAt(1, y, text, fg, bg) -- Écrit le texte de la barre avec les couleurs demandées.
end -- Termine la fonction d’affichage de barre.

local function centered(y, text, fg, bg) -- Déclare une fonction qui centre du texte horizontalement.
  writeAt(math.floor((w - #text) / 2) + 1, y, text, fg, bg) -- Calcule la colonne centrale puis affiche le texte.
end -- Termine la fonction de centrage.

-- Définit une version de os.pullEvent qui ignore Ctrl+T en mode kiosque.
local function pullEvent(filter) -- Déclare une fonction qui attend un événement, éventuellement filtré.
  while true do -- Répète l’attente jusqu’à obtenir un événement à renvoyer.
    local ev, a, b, c, d = os.pullEventRaw(filter) -- Récupère l’événement sans laisser Ctrl+T interrompre directement le programme.
    if ev == "terminate" then -- Vérifie si l’événement correspond à Ctrl+T.
      if not KIOSK then error("Terminated", 0) end -- En mode développement, propage l’interruption.
    else -- Traite tous les autres événements normalement.
      return ev, a, b, c, d -- Renvoie l’événement et ses paramètres.
    end -- Termine le traitement de cet événement.
  end -- Termine la boucle d’attente.
end -- Termine la fonction d’attente d’événement.

local function pause(seconds) -- Déclare une fonction qui attend une durée donnée sans bloquer les autres événements.
  local timer = os.startTimer(seconds) -- Démarre un minuteur pour la durée demandée.
  repeat -- Attend jusqu’à la fin du minuteur.
    local ev, id = pullEvent() -- Récupère les événements entrants.
  until ev == "timer" and id == timer -- Termine l’attente lorsque le minuteur demandé expire.
end -- Termine la fonction de pause.

local function waitKey() -- Déclare une fonction qui attend une pression de touche.
  pullEvent("key") -- Attend uniquement un événement clavier.
end -- Termine la fonction d’attente de touche.

-- Définit la saisie d’une ligne ; mask peut masquer un mot de passe avec des astérisques.
-- En mode kiosque, une tentative d’interruption relance la saisie.
local function ask(label, mask, x, y) -- Déclare une fonction de saisie avec invite et position facultative.
  local cx, cy = term.getCursorPos() -- Mémorise la position actuelle du curseur.
  x, y = x or cx, y or cy -- Utilise la position fournie ou celle du curseur.
  while true do -- Répète la saisie si Ctrl+T l’interrompt en mode kiosque.
    term.setBackgroundColor(colors.black) -- Définit le fond de la zone de saisie en noir.
    term.setTextColor(colors.white) -- Définit le texte de la zone de saisie en blanc.
    term.setCursorPos(x, y) -- Place le curseur à l’emplacement de l’invite.
    term.clearLine() -- Efface la ligne avant d’afficher l’invite.
    term.write(label) -- Affiche le texte qui demande une valeur à l’utilisateur.
    local ok, v = pcall(read, mask) -- Lance la saisie protégée et récupère son résultat.
    if ok then return v end -- Renvoie la valeur saisie si la lecture a réussi.
    if not KIOSK or not tostring(v):find("Terminated") then error(v, 0) end -- Propage toute erreur autre que l’interruption ignorée en mode kiosque.
  end -- Termine la boucle de saisie.
end -- Termine la fonction de saisie.

local function notice(text) -- Déclare une fonction qui affiche un message et attend une touche.
  term.setBackgroundColor(colors.black) -- Définit le fond du message en noir.
  term.setTextColor(colors.white) -- Définit le texte du message en blanc.
  print() -- Ajoute une ligne vide avant le message.
  print(text) -- Affiche le message fourni.
  print("Appuie sur une touche...") -- Demande à l’utilisateur d’appuyer sur une touche.
  waitKey() -- Attend cette pression de touche avant de continuer.
end -- Termine la fonction d’affichage de message.

-- =========================================================
--  Comptes utilisateurs
--  users[nom en minuscules] = { name, salt, h, admin }
-- =========================================================

local users = {} -- Stocke les comptes utilisateurs chargés en mémoire.

local function loadUsers() -- Déclare la fonction qui charge les comptes depuis le disque.
  if not fs.exists(USERS_FILE) then return end -- Arrête si le fichier des comptes n’existe pas.
  local f = fs.open(USERS_FILE, "r") -- Ouvre le fichier en lecture.
  if not f then return end -- Arrête si l’ouverture du fichier a échoué.
  local data = textutils.unserialize(f.readAll()) -- Lit le fichier et convertit son contenu en table Lua.
  f.close() -- Ferme le fichier après la lecture.
  if type(data) == "table" then users = data end -- Remplace les comptes en mémoire si les données sont valides.
end -- Termine la fonction de chargement des comptes.

local function saveUsers() -- Déclare la fonction qui sauvegarde les comptes sur le disque.
  if not fs.exists(DATA_DIR) then fs.makeDir(DATA_DIR) end -- Crée le dossier de données s’il n’existe pas.
  local f = fs.open(USERS_FILE, "w") -- Ouvre le fichier des comptes en écriture.
  f.write(textutils.serialize(users)) -- Convertit la table des comptes en texte et l’enregistre.
  f.close() -- Ferme le fichier après l’écriture.
end -- Termine la fonction de sauvegarde des comptes.

local function findUser(name) -- Déclare une fonction qui recherche un compte par son nom.
  if type(name) ~= "string" then return nil end -- Renvoie nil si le nom fourni n’est pas une chaîne.
  return users[name:lower()] -- Cherche le compte avec une clé insensible aux majuscules.
end -- Termine la fonction de recherche d’un compte.

local function userCount() -- Déclare une fonction qui compte les comptes enregistrés.
  local n = 0 -- Initialise le compteur.
  for _ in pairs(users) do n = n + 1 end -- Ajoute un au compteur pour chaque compte.
  return n -- Renvoie le nombre total de comptes.
end -- Termine la fonction de comptage des comptes.

local function adminCount() -- Déclare une fonction qui compte les comptes administrateurs.
  local n = 0 -- Initialise le compteur d’administrateurs.
  for _, u in pairs(users) do -- Parcourt tous les comptes enregistrés.
    if u.admin then n = n + 1 end -- Incrémente le compteur si le compte est administrateur.
  end -- Termine le parcours des comptes.
  return n -- Renvoie le nombre d’administrateurs.
end -- Termine la fonction de comptage des administrateurs.

local function validName(name) -- Déclare une fonction qui vérifie le format d’un nom de compte.
  return type(name) == "string" and #name >= 3 and #name <= 16 and name:match("^[%w_%-]+$") ~= nil -- Accepte les noms de 3 à 16 caractères contenant lettres, chiffres, _ ou -.
end -- Termine la validation du nom.

local function addUser(name, pw, admin) -- Déclare une fonction qui crée un compte utilisateur.
  if not validName(name) then -- Vérifie que le nom respecte le format attendu.
    return false, "Nom invalide (3-16 car. : lettres, chiffres, _ -)" -- Renvoie un échec et son explication.
  end -- Termine la vérification du nom.
  if #pw < MIN_PASSWORD then -- Vérifie que le mot de passe respecte la longueur minimale.
    return false, "Mot de passe trop court (min " .. MIN_PASSWORD .. ")" -- Renvoie un échec et la longueur requise.
  end -- Termine la vérification du mot de passe.
  if findUser(name) then return false, "Ce nom existe deja" end -- Refuse la création si le nom est déjà utilisé.
  local salt = randomHex(16) -- Génère une valeur aléatoire ajoutée au mot de passe avant le hash.
  users[name:lower()] = { name = name, salt = salt, h = sha256(salt .. pw), admin = admin and true or false } -- Enregistre le nom, le sel, le hash et le statut administrateur.
  saveUsers() -- Sauvegarde immédiatement les comptes modifiés.
  fs.makeDir(fs.combine(HOME_ROOT, name)) -- Crée le dossier personnel du nouvel utilisateur.
  return true -- Signale que la création du compte a réussi.
end -- Termine la fonction de création de compte.

local function checkPassword(rec, pw) -- Déclare une fonction qui vérifie un mot de passe.
  return rec ~= nil and sha256(rec.salt .. pw) == rec.h -- Compare le hash calculé au hash enregistré.
end -- Termine la vérification du mot de passe.

local function setPassword(rec, pw) -- Déclare une fonction qui remplace le mot de passe d’un compte.
  rec.salt = randomHex(16) -- Génère un nouveau sel pour le mot de passe.
  rec.h = sha256(rec.salt .. pw) -- Calcule et enregistre le hash du nouveau mot de passe.
  saveUsers() -- Sauvegarde les comptes après la modification.
end -- Termine la fonction de changement de mot de passe.

-- =========================================================
--  Session courante et reglages par utilisateur
-- =========================================================

local session = nil   -- Contiendra les informations du compte actuellement connecté.
local pendingAction = nil -- Contiendra éventuellement l’action demandée après le retour au bureau.

local function saveSettings() -- Déclare la fonction qui sauvegarde le thème de la session.
  local f = fs.open(fs.combine(session.home, ".settings"), "w") -- Ouvre le fichier de réglages du dossier personnel.
  if f then -- Vérifie que le fichier a pu être ouvert.
    f.write(textutils.serialize(theme)) -- Convertit le thème en texte et l’enregistre.
    f.close() -- Ferme le fichier après l’écriture.
  end -- Termine le traitement du fichier.
end -- Termine la sauvegarde du thème.

local function loadSettings() -- Déclare la fonction qui charge le thème personnel.
  resetTheme() -- Réinitialise d’abord le thème aux couleurs par défaut.
  local path = fs.combine(session.home, ".settings") -- Construit le chemin du fichier de réglages de l’utilisateur.
  if not fs.exists(path) then return end -- Arrête si cet utilisateur n’a pas encore de réglages.
  local f = fs.open(path, "r") -- Ouvre le fichier en lecture.
  if not f then return end -- Arrête si l’ouverture a échoué.
  local data = textutils.unserialize(f.readAll()) -- Lit le fichier et convertit son contenu en table Lua.
  f.close() -- Ferme le fichier après la lecture.
  if type(data) == "table" then -- Vérifie que le contenu chargé est une table.
    for k, v in pairs(data) do -- Parcourt les clés et valeurs du thème sauvegardé.
      if theme[k] ~= nil then theme[k] = v end -- Applique uniquement les clés déjà présentes dans le thème.
    end -- Termine le parcours du thème sauvegardé.
  end -- Termine la validation des réglages.
end -- Termine le chargement du thème.

-- =========================================================
--  Ecrans : premiere installation, connexion, verrouillage
-- =========================================================

local function setupScreen() -- Déclare l’écran de création initiale du compte administrateur.
  while true do -- Répète les demandes tant que le compte n’est pas créé.
    clear(colors.black, colors.white) -- Efface l’écran avec un fond noir et du texte blanc.
    bar(1, " " .. NAME .. " - premiere installation", theme.barText, theme.bar) -- Affiche le titre dans la barre supérieure.
    term.setBackgroundColor(colors.black) -- Définit le fond de la zone de texte.
    term.setTextColor(colors.white) -- Définit la couleur du texte.
    term.setCursorPos(1, 3) -- Place le curseur sous la barre de titre.
    print("Bienvenue ! Cree le compte administrateur.") -- Explique l’étape de première installation.
    print("(3-16 caracteres : lettres, chiffres, _ -)") -- Indique les règles de nommage.
    print() -- Ajoute une ligne vide pour aérer l’écran.
    local name = ask("Nom : ") -- Demande le nom du compte administrateur.
    local pw = ask("Mot de passe : ", "*") -- Demande le mot de passe en masquant sa saisie.
    local pw2 = ask("Confirme : ", "*") -- Demande une seconde saisie pour confirmer le mot de passe.
    if pw ~= pw2 then -- Vérifie que les deux mots de passe correspondent.
      notice("Les mots de passe different") -- Signale l’erreur et attend une touche.
    else -- Continue si les deux mots de passe correspondent.
      local ok, err = addUser(name, pw, true) -- Tente de créer le compte avec les droits administrateur.
      if ok then return end -- Quitte l’écran si le compte a été créé.
      notice(err) -- Affiche l’erreur renvoyée par la création du compte.
    end -- Termine la vérification des mots de passe.
  end -- Termine la boucle de première installation.
end -- Termine l’écran de première installation.

local loginFails = 0 -- Compte les échecs de connexion pour ralentir les essais successifs.

local function loginScreen() -- Déclare l’écran de connexion.
  while true do -- Répète la connexion jusqu’à la saisie d’identifiants valides.
    clear(colors.black, colors.white) -- Efface l’écran avant d’afficher le formulaire.
    bar(1, " " .. NAME .. " " .. VERSION, defaultTheme.barText, defaultTheme.bar) -- Affiche le nom et la version du système.
    local mid = math.floor(h / 2) -- Calcule la ligne verticale centrale de l’écran.
    centered(mid - 3, "Connexion", defaultTheme.accent, colors.black) -- Affiche le titre au centre.
    local name = ask("Utilisateur : ", nil, 2, mid - 1) -- Demande le nom de l’utilisateur.
    local pw = ask("Mot de passe : ", "*", 2, mid) -- Demande le mot de passe en masquant sa saisie.
    local rec = findUser(name) -- Recherche le compte correspondant au nom saisi.
    if checkPassword(rec, pw) then -- Vérifie que le compte existe et que son mot de passe est correct.
      loginFails = 0 -- Réinitialise le compteur d’échecs après une connexion réussie.
      return rec, pw -- Renvoie le compte et le mot de passe à la boucle de session.
    end -- Termine la vérification des identifiants.
    loginFails = loginFails + 1 -- Incrémente le compteur après une tentative incorrecte.
    centered(mid + 2, "Identifiants incorrects", colors.red, colors.black) -- Affiche un message d’erreur.
    pause(math.min(1 + loginFails, 8)) -- Ralentit les tentatives, jusqu’à une pause maximale de huit secondes.
  end -- Termine la boucle de connexion.
end -- Termine l’écran de connexion.

local function lockScreen() -- Déclare l’écran de verrouillage de la session active.
  local fails = 0 -- Initialise le compteur d’échecs de déverrouillage.
  while true do -- Répète la demande de mot de passe jusqu’au déverrouillage.
    clear(colors.black, colors.white) -- Efface l’écran avant d’afficher le verrouillage.
    local mid = math.floor(h / 2) -- Calcule la ligne verticale centrale de l’écran.
    centered(mid - 3, "Session verrouillee", theme.accent, colors.black) -- Affiche le titre de l’écran de verrouillage.
    centered(mid - 2, session.user, colors.white, colors.black) -- Affiche le nom de l’utilisateur connecté.
    local pw = ask("Mot de passe : ", "*", 2, mid) -- Demande le mot de passe en masquant la saisie.
    if checkPassword(findUser(session.user), pw) then return end -- Déverrouille et quitte la fonction si le mot de passe est valide.
    fails = fails + 1 -- Incrémente le compteur si le mot de passe est incorrect.
    centered(mid + 2, "Mot de passe incorrect", colors.red, colors.black) -- Affiche un message d’erreur.
    pause(math.min(1 + fails, 8)) -- Ralentit les nouvelles tentatives, jusqu’à huit secondes.
  end -- Termine la boucle de verrouillage.
end -- Termine l’écran de verrouillage.

-- =========================================================
--  Applications : chaque appli est une fonction sans argument
-- =========================================================

-- Terminal (administrateurs) : un shell classique, "exit" pour revenir
local function terminalApp() -- Déclare l’application Terminal.
  clear(colors.black, colors.white) -- Efface l’écran avec le thème du shell.
  print(NAME .. " - tape 'exit' pour revenir au bureau") -- Indique comment revenir au bureau.
  shell.setDir(session.home) -- Définit le dossier personnel comme dossier courant du shell.
  shell.run("shell") -- Lance un shell interactif.
end -- Termine l’application Terminal.

-- Fichiers : un utilisateur reste dans son dossier, un admin voit tout
local function filesApp() -- Déclare le gestionnaire de fichiers.
  local root = session.admin and "" or session.home -- Définit la limite de navigation selon le rôle du compte.
  local path, sel, scroll = session.home, 1, 0 -- Initialise le chemin, la sélection et le défilement.
  while true do -- Répète l’affichage et la gestion du gestionnaire.
    local list = fs.list(path) -- Récupère les éléments du dossier courant.
    table.sort(list, function(a, b) -- Trie les éléments avant de les afficher.
      local da, db = fs.isDir(fs.combine(path, a)), fs.isDir(fs.combine(path, b)) -- Détermine lesquels sont des dossiers.
      if da ~= db then return da end -- Place les dossiers avant les fichiers.
      return a:lower() < b:lower() -- Trie les éléments de même type par nom, sans tenir compte de la casse.
    end) -- Termine le tri de la liste.

    if sel > #list then sel = math.max(#list, 1) end -- Maintient la sélection dans les limites de la liste.
    local rows = h - 2 -- Calcule le nombre de lignes disponibles pour afficher les éléments.
    if sel <= scroll then scroll = sel - 1 end -- Déplace l’affichage si la sélection est au-dessus de la zone visible.
    if sel > scroll + rows then scroll = sel - rows end -- Déplace l’affichage si la sélection est sous la zone visible.

    clear(colors.black, colors.white) -- Efface l’écran avant de redessiner le gestionnaire.
    bar(1, " /" .. path, theme.barText, theme.bar) -- Affiche le chemin courant dans la barre supérieure.
    for i = 1, rows do -- Parcourt les lignes disponibles pour afficher les éléments.
      local name = list[scroll + i] -- Récupère le nom de l’élément correspondant à cette ligne.
      if not name then break end -- Arrête l’affichage lorsqu’il n’y a plus d’élément.
      local isDir = fs.isDir(fs.combine(path, name)) -- Vérifie si l’élément est un dossier.
      local selected = (scroll + i == sel) -- Vérifie si l’élément est sélectionné.
      local line = " " .. name .. (isDir and "/" or "") -- Prépare le nom et ajoute / si c’est un dossier.
      line = line .. string.rep(" ", w - #line) -- Complète la ligne avec des espaces jusqu’à la largeur de l’écran.
      writeAt(1, 1 + i, line, -- Affiche l’élément à la ligne correspondante.
        selected and colors.black or (isDir and colors.yellow or colors.white), -- Choisit la couleur du texte selon la sélection et le type.
        selected and theme.accent or colors.black) -- Met en évidence l’élément sélectionné avec la couleur d’accent.
    end -- Termine l’affichage des éléments.
    bar(h, " Entree:ouvrir Retour:parent Q:quitter", theme.barText, theme.bar) -- Affiche les commandes du gestionnaire.

    local _, key = pullEvent("key") -- Attend une touche et récupère son code.
    if key == keys.up and sel > 1 then -- Vérifie si la touche Haut peut déplacer la sélection.
      sel = sel - 1 -- Déplace la sélection vers l’élément précédent.
    elseif key == keys.down and sel < #list then -- Vérifie si la touche Bas peut déplacer la sélection.
      sel = sel + 1 -- Déplace la sélection vers l’élément suivant.
    elseif key == keys.backspace and path ~= root then -- Vérifie si l’utilisateur peut remonter au dossier parent.
      path = fs.getDir(path) -- Remonte d’un niveau dans l’arborescence.
      sel, scroll = 1, 0 -- Replace la sélection et le défilement au début de la liste.
    elseif key == keys.enter and list[sel] then -- Vérifie si Entrée a été pressée avec un élément sélectionné.
      local full = fs.combine(path, list[sel]) -- Construit le chemin complet de l’élément sélectionné.
      if fs.isDir(full) then -- Vérifie si l’élément sélectionné est un dossier.
        path = full -- Entre dans le dossier sélectionné.
        sel, scroll = 1, 0 -- Réinitialise la sélection et le défilement dans ce dossier.
      else -- Traite l’élément comme un fichier.
        shell.run("edit", full) -- Ouvre le fichier dans l’éditeur intégré.
      end -- Termine le traitement du dossier ou du fichier.
    elseif key == keys.q then -- Vérifie si la touche Q a été pressée.
      return -- Quitte le gestionnaire et revient au bureau.
    end -- Termine le traitement de la touche.
  end -- Termine la boucle du gestionnaire de fichiers.
end -- Termine l’application Fichiers.

-- Bloc-notes : notes.txt dans le dossier personnel
local function notesApp() -- Déclare l’application Bloc-notes.
  shell.run("edit", fs.combine(session.home, "notes.txt")) -- Ouvre le fichier notes.txt du dossier personnel dans l’éditeur.
end -- Termine l’application Bloc-notes.

-- Horloge : heure du jeu + heure reelle du serveur
local function clockApp() -- Déclare l’application Horloge.
  while true do -- Répète l’affichage jusqu’à ce que l’utilisateur quitte.
    clear(colors.black, colors.white) -- Efface l’écran avant de redessiner l’horloge.
    local mid = math.floor(h / 2) -- Calcule la ligne verticale centrale de l’écran.
    centered(mid - 2, "Heure du jeu", colors.lightGray, colors.black) -- Affiche le titre de l’heure du jeu.
    centered(mid - 1, textutils.formatTime(os.time(), true), theme.accent, colors.black) -- Affiche l’heure du jeu au format court.
    centered(mid + 1, "Jour " .. os.day(), colors.white, colors.black) -- Affiche le numéro du jour dans le jeu.
    centered(mid + 3, "Heure reelle (serveur)", colors.lightGray, colors.black) -- Affiche le titre de l’heure réelle.
    centered(mid + 4, os.date("%H:%M:%S"), theme.accent, colors.black) -- Affiche l’heure réelle du serveur.
    centered(h, "Une touche pour quitter", colors.gray, colors.black) -- Indique comment quitter l’horloge.

    local timer = os.startTimer(1) -- Démarre un minuteur pour actualiser l’affichage après une seconde.
    repeat -- Attend la touche de sortie ou la fin du minuteur.
      local ev, a = pullEvent() -- Récupère l’événement et son premier paramètre.
      if ev == "key" or ev == "mouse_click" then return end -- Quitte l’application si une touche ou un clic survient.
    until ev == "timer" and a == timer -- Recommence l’affichage quand le minuteur de cette seconde expire.
  end -- Termine la boucle de l’horloge.
end -- Termine l’application Horloge.

-- ---------------------------------------------------------
--  Messagerie : passe par un ordinateur "minios_server".
--  Ta session sert de compte de messagerie (meme nom, meme mot
--  de passe) ; le compte est cree automatiquement la 1re fois.
-- ---------------------------------------------------------

local function openModem() -- Déclare une fonction qui cherche et ouvre un modem.
  for _, name in ipairs(peripheral.getNames()) do -- Parcourt les noms des périphériques connectés.
    if peripheral.getType(name) == "modem" then -- Vérifie si le périphérique courant est un modem.
      if not rednet.isOpen(name) then rednet.open(name) end -- Ouvre le modem pour rednet s’il ne l’est pas déjà.
      return true -- Signale qu’un modem est disponible.
    end -- Termine la vérification du périphérique.
  end -- Termine le parcours des périphériques.
  return false -- Signale qu’aucun modem n’a été trouvé.
end -- Termine la recherche de modem.

-- Envoie une requete au serveur et attend sa reponse (nil si rien)
local function request(serverId, tbl, timeout) -- Déclare une fonction d’envoi de requête avec délai d’attente.
  rednet.send(serverId, tbl, AUTH) -- Envoie la table au serveur avec le protocole d’authentification.
  local deadline = os.startTimer(timeout or 3) -- Démarre le délai d’attente, trois secondes par défaut.
  while true do -- Attend la réponse ou l’expiration du délai.
    local ev, a, b, c = pullEvent() -- Récupère un événement réseau ou de minuterie.
    if ev == "rednet_message" and a == serverId and c == AUTH and type(b) == "table" then -- Vérifie que le message vient du serveur, utilise le bon protocole et contient une table.
      os.cancelTimer(deadline) -- Annule le minuteur puisque la réponse a été reçue.
      return b -- Renvoie le contenu de la réponse.
    elseif ev == "timer" and a == deadline then -- Vérifie si le délai d’attente est expiré.
      return nil -- Renvoie nil en l’absence de réponse.
    end -- Termine le traitement de l’événement.
  end -- Termine l’attente de la réponse.
end -- Termine la fonction de requête réseau.

local function register(serverId, user, pw) -- Déclare une fonction d’inscription auprès du serveur.
  local salt = randomHex(16) -- Génère un sel aléatoire pour le mot de passe.
  local r = request(serverId, { t = "reg", u = user, salt = salt, h = sha256(salt .. pw) }) -- Envoie le nom, le sel et le hash du mot de passe au serveur.
  if not r then return false, "Le serveur ne repond pas" end -- Signale l’absence de réponse du serveur.
  if r.t == "ok" then return true end -- Signale que l’inscription a réussi.
  return false, r.x or "Erreur" -- Renvoie l’erreur fournie par le serveur ou un message générique.
end -- Termine la fonction d’inscription.

-- Connexion par defi : le mot de passe ne circule jamais sur la radio
local function login(serverId, user, pw) -- Déclare une fonction de connexion au serveur par défi.
  local r = request(serverId, { t = "hello", u = user }) -- Demande au serveur les informations nécessaires au défi.
  if not r then return nil, "Le serveur ne repond pas" end -- Signale que le serveur n’a pas répondu.
  if r.t ~= "chal" then return nil, r.x or "Erreur" end -- Vérifie que le serveur a bien envoyé un défi.
  if type(r.salt) ~= "string" or type(r.n) ~= "string" then return nil, "Reponse invalide" end -- Vérifie que le sel et le nombre aléatoire sont des chaînes.
  local sk = hmac(sha256(r.salt .. pw), r.n) -- Dérive une clé de session à partir du mot de passe et du défi.
  local r2 = request(serverId, { t = "login", p = hmac(sk, "login") }) -- Envoie une preuve calculée avec la clé de session.
  if not r2 then return nil, "Le serveur ne repond pas" end -- Signale que le serveur n’a pas répondu à la preuve.
  if r2.t ~= "ok" then return nil, r2.x or "Erreur" end -- Vérifie que le serveur a accepté la connexion.
  return r2.user, sk -- Renvoie le nom de compte et la clé de session.
end -- Termine la fonction de connexion.

-- Saisie manuelle (si le compte de messagerie a un autre mot de passe)
local function authScreen(serverId) -- Déclare l’écran de connexion ou de création d’un compte de messagerie.
  while true do -- Répète le menu jusqu’à une connexion ou un retour.
    clear(colors.black, colors.white) -- Efface l’écran avant d’afficher le menu.
    bar(1, " Messagerie - compte", theme.barText, theme.bar) -- Affiche le titre de l’écran.
    term.setBackgroundColor(colors.black) -- Définit le fond de la zone de menu.
    term.setTextColor(colors.white) -- Définit la couleur du texte du menu.
    term.setCursorPos(1, 3) -- Place le curseur sous la barre supérieure.
    print("1) Connexion") -- Propose de se connecter à un compte existant.
    print("2) Creer un compte") -- Propose de créer un compte de messagerie.
    print("Q) Retour") -- Propose de revenir à l’application précédente.
    print() -- Ajoute une ligne vide avant la saisie.
    local choice = ask("> "):lower() -- Demande un choix et le convertit en minuscules.
    if choice == "q" then return nil end -- Retourne au menu précédent si Q est saisi.

    if choice == "1" or choice == "2" then -- Traite uniquement les choix de connexion ou de création.
      local user = ask("Nom : ") -- Demande le nom du compte de messagerie.
      local pw = ask("Mot de passe : ", "*") -- Demande le mot de passe en masquant la saisie.
      local ok, err = true, nil -- Initialise le statut et le message d’erreur.

      if choice == "2" then -- Effectue les étapes supplémentaires pour une création de compte.
        if ask("Confirme : ", "*") ~= pw then -- Vérifie que le mot de passe confirmé correspond.
          ok, err = false, "Les mots de passe different" -- Prépare un échec si les saisies diffèrent.
        else -- Continue si les deux mots de passe correspondent.
          ok, err = register(serverId, user, pw) -- Tente d’inscrire le compte sur le serveur.
        end -- Termine le traitement de la confirmation.
      end -- Termine le traitement spécifique à la création.

      if ok then -- Tente la connexion si les étapes précédentes ont réussi.
        local name, sk = login(serverId, user, pw) -- Demande au serveur d’authentifier le compte.
        if name then return name, sk end -- Renvoie le compte et sa clé de session si la connexion réussit.
        err = sk -- Récupère le message d’erreur renvoyé comme second résultat.
      end -- Termine la tentative de connexion.
      notice(err or "Erreur") -- Affiche l’erreur ou un message générique.
    end -- Termine le traitement du choix.
  end -- Termine la boucle du menu d’authentification.
end -- Termine l’écran d’authentification.

local function chatApp() -- Déclare l’application de messagerie.
  clear(colors.black, colors.white) -- Efface l’écran avant de lancer les vérifications.
  if not openModem() then -- Vérifie qu’un modem est disponible.
    print("Aucun modem detecte.") -- Informe qu’aucun modem n’a été trouvé.
    print("Place un modem contre l'ordinateur.") -- Indique comment connecter un modem.
    print() -- Ajoute une ligne vide.
    print("Appuie sur une touche...") -- Demande à l’utilisateur d’appuyer sur une touche.
    waitKey() -- Attend une touche avant de revenir au bureau.
    return -- Quitte l’application.
  end -- Termine la vérification du modem.

  local serverId = rednet.lookup(AUTH, "minios-server") -- Recherche un serveur qui annonce le service MiniOS.
  if not serverId then -- Vérifie si aucun serveur n’a été trouvé.
    print("Serveur de messagerie introuvable.") -- Informe que le service n’est pas disponible.
    print("Lance minios_server sur un ordinateur") -- Indique la première étape pour démarrer le serveur.
    print("avec modem, a portee radio.") -- Indique qu’un modem à portée radio est nécessaire.
    print() -- Ajoute une ligne vide.
    print("Appuie sur une touche...") -- Demande à l’utilisateur d’appuyer sur une touche.
    waitKey() -- Attend une touche avant de revenir au bureau.
    return -- Quitte l’application.
  end -- Termine la vérification du serveur.

  -- 1) connexion automatique avec la session ; 2) creation du compte
  -- de messagerie s'il n'existe pas ; 3) saisie manuelle en dernier recours
  local me, sk = login(serverId, session.user, session.pw) -- Tente d’utiliser les identifiants de la session MiniOS.
  if not me then -- Continue si la connexion automatique a échoué.
    local ok, err = register(serverId, session.user, session.pw) -- Tente de créer un compte de messagerie avec les identifiants de la session.
    if ok then -- Continue si la création du compte a réussi.
      me, sk = login(serverId, session.user, session.pw) -- Réessaie la connexion avec le compte créé.
    else -- Traite l’échec de la création du compte.
      notice("Connexion automatique impossible : " .. tostring(err)) -- Affiche la raison de l’échec.
    end -- Termine le traitement de la création automatique.
  end -- Termine la tentative d’inscription automatique.
  if not me then me, sk = authScreen(serverId) end -- Demande une connexion manuelle si les tentatives automatiques ont échoué.
  if not me then return end -- Quitte si l’utilisateur a choisi de revenir en arrière.

  local log, input, counter = {}, "", 0 -- Initialise le journal, le texte saisi et le compteur de messages.

  local function addLog(text) -- Déclare une fonction qui ajoute du texte au journal de discussion.
    while #text > 0 do -- Continue tant qu’il reste du texte à traiter.
      table.insert(log, text:sub(1, w)) -- Ajoute au journal un segment ne dépassant pas la largeur de l’écran.
      text = text:sub(w + 1) -- Retire du texte le segment qui vient d’être ajouté.
    end -- Termine le découpage du texte.
  end -- Termine la fonction d’ajout au journal.

  -- Chaque message est signe avec la cle de session et numerote
  local function send(kind, to, text) -- Déclare une fonction qui envoie un message authentifié.
    counter = counter + 1 -- Incrémente le numéro de séquence des messages.
    rednet.send(serverId, { -- Envoie une table contenant les informations du message.
      t = kind, c = counter, to = to, x = text, -- Ajoute le type, le numéro, le destinataire et le texte du message.
      s = hmac(sk, table.concat({ counter, kind, to or "", text or "" }, "|")), -- Calcule une signature HMAC des champs du message.
    }, AUTH) -- Utilise le protocole d’authentification pour l’envoi.
  end -- Termine la fonction d’envoi de message.

  local function draw() -- Déclare une fonction qui redessine l’interface de discussion.
    clear(colors.black, colors.white) -- Efface l’écran.
    bar(1, " Chat - " .. me .. "  (ID " .. os.getComputerID() .. ")", theme.barText, theme.bar) -- Affiche le nom et l’identifiant de l’ordinateur.
    local rows = h - 2 -- Calcule le nombre de lignes disponibles pour le journal.
    local first = math.max(1, #log - rows + 1) -- Calcule l’index du premier message visible.
    for i = first, #log do -- Parcourt les messages visibles.
      writeAt(1, 2 + i - first, log[i], colors.white, colors.black) -- Affiche chaque message à sa ligne.
    end -- Termine l’affichage du journal.
    writeAt(1, h, "> " .. input:sub(-(w - 3)) .. "_", theme.accent, colors.black) -- Affiche la fin de la saisie en cours et le curseur.
  end -- Termine la fonction de dessin de la messagerie.

  addLog("Connecte : " .. me) -- Ajoute au journal le nom du compte connecté.
  addLog("/w nom message = prive, /quit = sortir") -- Affiche les commandes de messagerie disponibles.
  while true do -- Répète l’affichage et le traitement des événements.
    draw() -- Met à jour l’écran avant d’attendre un événement.
    local ev, a, b, c = pullEvent() -- Récupère un événement et ses paramètres.
    if ev == "char" then -- Traite la saisie d’un caractère.
      input = input .. a -- Ajoute le caractère au texte en cours.
    elseif ev == "key" then -- Traite les touches de commande.
      if a == keys.backspace then -- Vérifie si Retour arrière a été pressée.
        input = input:sub(1, -2) -- Supprime le dernier caractère saisi.
      elseif a == keys.enter then -- Vérifie si Entrée a été pressée.
        local text = input -- Copie le texte saisi pour le traiter.
        input = "" -- Vide le champ de saisie.
        if text == "/quit" then -- Vérifie si l’utilisateur demande à quitter.
          send("bye") -- Informe le serveur que l’utilisateur quitte la messagerie.
          return -- Quitte l’application de messagerie.
        elseif text:sub(1, 3) == "/w " then -- Vérifie si le texte commence par la commande de message privé.
          local to, msg = text:match("^/w%s+(%S+)%s+(.+)$") -- Extrait le destinataire et le texte du message privé.
          if to then send("msg", to, msg) else addLog("Usage : /w nom message") end -- Envoie le message privé ou affiche la syntaxe attendue.
        elseif text ~= "" then -- Vérifie qu’un message normal n’est pas vide.
          send("msg", nil, text) -- Envoie un message public au serveur.
        end -- Termine le traitement du texte saisi.
      end -- Termine le traitement de la touche.
    elseif ev == "rednet_message" and a == serverId and type(b) == "table" then -- Vérifie qu’un message du serveur contient une table.
      if c == CHAT then -- Traite les messages du protocole de discussion.
        if b.t == "chat" and type(b.from) == "string" and type(b.x) == "string" then -- Vérifie le type et les champs d’un message de discussion.
          if b.to then -- Vérifie si le message est privé.
            if b.from == me then -- Vérifie si le message vient de l’utilisateur actuel.
              addLog("[MP a " .. tostring(b.to) .. "] " .. b.x) -- Affiche le message privé envoyé et son destinataire.
            else -- Traite un message privé reçu d’un autre utilisateur.
              addLog("[MP de " .. b.from .. "] " .. b.x) -- Affiche le message privé reçu et son expéditeur.
            end -- Termine l’affichage du message privé.
          else -- Traite un message public.
            addLog(b.from .. ": " .. b.x) -- Affiche le nom de l’expéditeur et le texte.
          end -- Termine le traitement du caractère privé ou public.
        elseif b.t == "sys" and type(b.x) == "string" then -- Vérifie s’il s’agit d’un message système.
          addLog("* " .. b.x) -- Affiche le message système dans le journal.
        end -- Termine le traitement des messages de discussion.
      elseif c == AUTH and b.t == "err" and type(b.x) == "string" then -- Vérifie si le serveur a envoyé une erreur d’authentification.
        addLog("! " .. b.x) -- Affiche l’erreur reçue du serveur.
      end -- Termine le traitement du protocole reçu.
    end -- Termine le traitement de l’événement.
  end -- Termine la boucle de messagerie.
end -- Termine l’application de messagerie.

-- ---------------------------------------------------------
--  Reglages : couleurs du theme (propres a chaque utilisateur)
-- ---------------------------------------------------------

local palette = { -- Définit les couleurs accessibles dans l’application Réglages.
  colors.blue, colors.cyan, colors.green, colors.lime, colors.orange, -- Ajoute les premières couleurs disponibles.
  colors.red, colors.purple, colors.magenta, colors.brown, colors.gray, -- Ajoute les autres couleurs disponibles.
  colors.black, -- Ajoute le noir à la palette.
} -- Termine la définition de la palette.

local function nextColor(current, dir) -- Déclare une fonction qui choisit la couleur suivante ou précédente.
  local idx = 1 -- Initialise la position supposée de la couleur courante.
  for i, c in ipairs(palette) do -- Parcourt les couleurs de la palette.
    if c == current then idx = i end -- Enregistre la position de la couleur actuelle.
  end -- Termine la recherche de la couleur.
  idx = (idx - 1 + dir) % #palette + 1 -- Avance ou recule dans la palette en bouclant aux extrémités.
  return palette[idx] -- Renvoie la couleur choisie.
end -- Termine la fonction de changement de couleur.

local function settingsApp() -- Déclare l’application de réglage des couleurs.
  local items = { -- Définit les réglages affichés dans le menu.
    { label = "Fond du bureau", key = "bg" }, -- Associe le réglage de fond à la clé bg du thème.
    { label = "Barres",         key = "bar" }, -- Associe les barres à la clé bar du thème.
    { label = "Accent",         key = "accent" }, -- Associe la couleur d’accent à la clé accent.
  } -- Termine la liste des réglages.
  local sel = 1 -- Sélectionne le premier réglage au démarrage.
  while true do -- Répète l’affichage et le traitement des touches.
    clear(colors.black, colors.white) -- Efface l’écran.
    bar(1, " Reglages", theme.barText, theme.bar) -- Affiche le titre dans la barre supérieure.
    for i, item in ipairs(items) do -- Parcourt les réglages à afficher.
      local y = 1 + i * 2 -- Calcule la ligne d’affichage de chaque réglage.
      writeAt(2, y, (i == sel and "> " or "  ") .. item.label, colors.white, colors.black) -- Affiche le nom du réglage et l’indicateur de sélection.
      writeAt(w - 5, y, "    ", colors.white, theme[item.key]) -- Affiche un aperçu de la couleur actuelle du réglage.
    end -- Termine l’affichage des réglages.
    bar(h, " Fleches:changer  Q:retour", theme.barText, theme.bar) -- Affiche les commandes disponibles.

    local _, key = pullEvent("key") -- Attend une touche et récupère son code.
    if key == keys.up and sel > 1 then -- Vérifie si la sélection peut remonter.
      sel = sel - 1 -- Sélectionne le réglage précédent.
    elseif key == keys.down and sel < #items then -- Vérifie si la sélection peut descendre.
      sel = sel + 1 -- Sélectionne le réglage suivant.
    elseif key == keys.left then -- Vérifie si la flèche gauche a été pressée.
      theme[items[sel].key] = nextColor(theme[items[sel].key], -1) -- Applique la couleur précédente au réglage sélectionné.
    elseif key == keys.right then -- Vérifie si la flèche droite a été pressée.
      theme[items[sel].key] = nextColor(theme[items[sel].key], 1) -- Applique la couleur suivante au réglage sélectionné.
    elseif key == keys.q then -- Vérifie si la touche Q a été pressée.
      saveSettings() -- Enregistre le thème modifié dans le dossier personnel.
      return -- Quitte l’application Réglages.
    end -- Termine le traitement de la touche.
  end -- Termine la boucle des réglages.
end -- Termine l’application Réglages.

-- ---------------------------------------------------------
--  Comptes : mot de passe pour tous, gestion pour les admins
-- ---------------------------------------------------------

local function changeOwnPassword() -- Déclare la fonction de changement du mot de passe personnel.
  local rec = findUser(session.user) -- Récupère l’enregistrement du compte connecté.
  local old = ask("Mot de passe actuel : ", "*") -- Demande le mot de passe actuel en le masquant.
  if not checkPassword(rec, old) then return notice("Mot de passe incorrect") end -- Refuse la modification si l’ancien mot de passe est incorrect.
  local p1 = ask("Nouveau mot de passe : ", "*") -- Demande le nouveau mot de passe.
  local p2 = ask("Confirme : ", "*") -- Demande de confirmer le nouveau mot de passe.
  if p1 ~= p2 then return notice("Les mots de passe different") end -- Refuse la modification si les deux saisies diffèrent.
  if #p1 < MIN_PASSWORD then return notice("Trop court (min " .. MIN_PASSWORD .. ")") end -- Refuse le mot de passe s’il est trop court.
  setPassword(rec, p1) -- Enregistre le nouveau mot de passe du compte.
  session.pw = p1 -- Met à jour le mot de passe conservé dans la session.
  notice("Mot de passe modifie.") -- Confirme que le mot de passe a été changé.
end -- Termine la fonction de changement de mot de passe.

local function listUsers() -- Déclare une fonction qui affiche la liste des comptes.
  clear(colors.black, colors.white) -- Efface l’écran.
  bar(1, " Utilisateurs", theme.barText, theme.bar) -- Affiche le titre dans la barre supérieure.
  local names = {} -- Crée une liste temporaire pour les comptes à afficher.
  for _, u in pairs(users) do names[#names + 1] = u end -- Copie les enregistrements des comptes dans la liste temporaire.
  table.sort(names, function(a, b) return a.name:lower() < b.name:lower() end) -- Trie les comptes par nom sans tenir compte de la casse.
  for i, u in ipairs(names) do -- Parcourt les comptes triés.
    writeAt(2, 2 + i, u.name .. (u.admin and "  [admin]" or ""), colors.white, colors.black) -- Affiche le nom et indique le statut administrateur.
  end -- Termine l’affichage des comptes.
  term.setCursorPos(1, h) -- Place le curseur sur la dernière ligne.
  term.setTextColor(colors.gray) -- Choisit une couleur grise pour l’instruction.
  term.write("Une touche pour revenir") -- Indique comment retourner au menu.
  waitKey() -- Attend une touche avant de quitter l’écran.
end -- Termine l’affichage de la liste des comptes.

local function createUser() -- Déclare la fonction de création d’un compte depuis le menu.
  local name = ask("Nom : ") -- Demande le nom du nouveau compte.
  local pw = ask("Mot de passe : ", "*") -- Demande le mot de passe en masquant la saisie.
  if ask("Confirme : ", "*") ~= pw then return notice("Les mots de passe different") end -- Vérifie la confirmation du mot de passe.
  local admin = ask("Administrateur ? (o/n) : "):lower() == "o" -- Détermine si le nouveau compte aura les droits administrateur.
  local ok, err = addUser(name, pw, admin) -- Tente de créer le compte avec les informations saisies.
  notice(ok and ("Utilisateur " .. name .. " cree.") or err) -- Affiche le résultat de la création.
end -- Termine la fonction de création de compte.

local function deleteUser() -- Déclare la fonction de suppression d’un compte.
  local rec = findUser(ask("Nom a supprimer : ")) -- Demande le nom du compte et recherche son enregistrement.
  if not rec then return notice("Utilisateur inconnu") end -- Arrête si le compte n’existe pas.
  if rec.name:lower() == session.user:lower() then -- Vérifie si le compte demandé est celui de la session actuelle.
    return notice("Tu ne peux pas supprimer ton propre compte") -- Empêche l’utilisateur de supprimer son propre compte.
  end -- Termine la vérification du compte courant.
  if rec.admin and adminCount() <= 1 then -- Vérifie si ce compte est le dernier administrateur.
    return notice("Impossible : dernier administrateur") -- Empêche la suppression du dernier administrateur.
  end -- Termine la vérification du nombre d’administrateurs.
  if ask("Supprimer " .. rec.name .. " ? (o/n) : "):lower() ~= "o" then return end -- Demande confirmation avant de poursuivre.
  local wipe = ask("Supprimer aussi son dossier ? (o/n) : "):lower() == "o" -- Demande si le dossier personnel doit aussi être supprimé.
  users[rec.name:lower()] = nil -- Retire le compte de la table des utilisateurs.
  saveUsers() -- Enregistre la liste des comptes modifiée.
  if wipe then fs.delete(fs.combine(HOME_ROOT, rec.name)) end -- Supprime le dossier personnel si l’utilisateur l’a demandé.
  notice("Utilisateur supprime.") -- Confirme la suppression du compte.
end -- Termine la fonction de suppression de compte.

local function resetPassword() -- Déclare la fonction de réinitialisation d’un mot de passe par un administrateur.
  local rec = findUser(ask("Nom : ")) -- Demande le nom du compte et récupère son enregistrement.
  if not rec then return notice("Utilisateur inconnu") end -- Arrête si le compte demandé n’existe pas.
  local p1 = ask("Nouveau mot de passe : ", "*") -- Demande le nouveau mot de passe.
  local p2 = ask("Confirme : ", "*") -- Demande sa confirmation.
  if p1 ~= p2 then return notice("Les mots de passe different") end -- Refuse si les deux mots de passe ne correspondent pas.
  if #p1 < MIN_PASSWORD then return notice("Trop court (min " .. MIN_PASSWORD .. ")") end -- Refuse si le mot de passe est trop court.
  setPassword(rec, p1) -- Enregistre le nouveau mot de passe.
  if rec.name:lower() == session.user:lower() then session.pw = p1 end -- Met à jour le mot de passe en mémoire si le compte est celui de la session.
  notice("Mot de passe reinitialise.") -- Confirme la réinitialisation.
end -- Termine la fonction de réinitialisation.

local function accountsApp() -- Déclare l’application de gestion des comptes.
  while true do -- Répète le menu jusqu’au retour au bureau.
    clear(colors.black, colors.white) -- Efface l’écran.
    bar(1, " Comptes - " .. session.user, theme.barText, theme.bar) -- Affiche le titre et le nom du compte connecté.
    term.setBackgroundColor(colors.black) -- Définit le fond du menu.
    term.setTextColor(colors.white) -- Définit la couleur du texte.
    term.setCursorPos(1, 3) -- Place le curseur sous le titre.
    print("1) Changer mon mot de passe") -- Propose à tous les utilisateurs de changer leur mot de passe.
    if session.admin then -- Vérifie si l’utilisateur connecté est administrateur.
      print("2) Liste des utilisateurs") -- Propose d’afficher les comptes.
      print("3) Creer un utilisateur") -- Propose de créer un compte.
      print("4) Supprimer un utilisateur") -- Propose de supprimer un compte.
      print("5) Reinitialiser un mot de passe") -- Propose de réinitialiser un mot de passe.
    end -- Termine l’affichage des options réservées aux administrateurs.
    print("Q) Retour") -- Propose de revenir au bureau.
    print() -- Ajoute une ligne vide avant l’invite.
    local choice = ask("> "):lower() -- Demande un choix et le convertit en minuscules.
    if choice == "q" then return end -- Quitte l’application si Q est saisi.
    if choice == "1" then -- Vérifie si l’utilisateur veut changer son mot de passe.
      changeOwnPassword() -- Lance la procédure de changement personnel.
    elseif session.admin and choice == "2" then -- Vérifie si un administrateur a demandé la liste des comptes.
      listUsers() -- Affiche les comptes enregistrés.
    elseif session.admin and choice == "3" then -- Vérifie si un administrateur veut créer un compte.
      createUser() -- Lance la création d’un compte.
    elseif session.admin and choice == "4" then -- Vérifie si un administrateur veut supprimer un compte.
      deleteUser() -- Lance la suppression d’un compte.
    elseif session.admin and choice == "5" then -- Vérifie si un administrateur veut réinitialiser un mot de passe.
      resetPassword() -- Lance la procédure de réinitialisation.
    end -- Termine le traitement du choix du menu.
  end -- Termine la boucle de l’application.
end -- Termine l’application Comptes.

-- ---------------------------------------------------------
--  Menu Session : verrouiller, deconnexion, alimentation
-- ---------------------------------------------------------

local function sessionApp() -- Déclare l’application de gestion de la session et de l’ordinateur.
  while true do -- Répète le menu jusqu’à ce qu’une action le ferme.
    clear(colors.black, colors.white) -- Efface l’écran.
    bar(1, " Session - " .. session.user, theme.barText, theme.bar) -- Affiche le titre et le nom de l’utilisateur.
    term.setBackgroundColor(colors.black) -- Définit le fond du menu.
    term.setTextColor(colors.white) -- Définit la couleur du texte.
    term.setCursorPos(1, 3) -- Place le curseur sous le titre.
    print("1) Verrouiller") -- Propose de verrouiller la session.
    print("2) Se deconnecter") -- Propose de fermer la session utilisateur.
    print("3) Redemarrer") -- Propose de redémarrer l’ordinateur.
    print("4) Eteindre") -- Propose d’éteindre l’ordinateur.
    if session.admin then print("5) Quitter vers CraftOS") end -- Affiche l’option de sortie vers CraftOS aux administrateurs.
    print("Q) Retour") -- Propose de revenir au bureau.
    print() -- Ajoute une ligne vide avant l’invite.
    local choice = ask("> "):lower() -- Demande un choix et le convertit en minuscules.
    if choice == "1" then -- Vérifie si l’utilisateur veut verrouiller la session.
      lockScreen() -- Affiche l’écran de verrouillage.
      return -- Revient au bureau après le déverrouillage.
    elseif choice == "2" then -- Vérifie si l’utilisateur veut se déconnecter.
      pendingAction = "logout" -- Demande à la boucle principale de fermer la session.
      return -- Quitte l’application pour transmettre l’action au bureau.
    elseif choice == "3" then -- Vérifie si l’utilisateur veut redémarrer.
      os.reboot() -- Redémarre l’ordinateur.
      return -- Termine la fonction si l’appel au redémarrage revient.
    elseif choice == "4" then -- Vérifie si l’utilisateur veut éteindre.
      os.shutdown() -- Éteint l’ordinateur.
      return -- Termine la fonction si l’appel à l’arrêt revient.
    elseif choice == "5" and session.admin then -- Vérifie que l’administrateur demande la sortie vers CraftOS.
      pendingAction = "exit" -- Demande à la boucle principale de quitter MiniOS.
      return -- Quitte l’application pour transmettre l’action au bureau.
    elseif choice == "q" then -- Vérifie si l’utilisateur veut simplement revenir.
      return -- Quitte l’application et revient au bureau.
    end -- Termine le traitement du choix.
  end -- Termine la boucle du menu de session.
end -- Termine l’application Session.

-- =========================================================
--  Registre des applications : ajoutes-en une ici !
--  admin = true : visible seulement pour les administrateurs
-- =========================================================

local apps = { -- Définit les applications disponibles dans MiniOS.
  { name = "Terminal",   run = terminalApp, admin = true }, -- Ajoute le terminal, réservé aux administrateurs.
  { name = "Fichiers",   run = filesApp }, -- Ajoute le gestionnaire de fichiers.
  { name = "Bloc-notes", run = notesApp }, -- Ajoute le bloc-notes.
  { name = "Horloge",    run = clockApp }, -- Ajoute l’horloge.
  { name = "Messagerie", run = chatApp }, -- Ajoute la messagerie.
  { name = "Reglages",   run = settingsApp }, -- Ajoute les réglages du thème.
  { name = "Comptes",    run = accountsApp }, -- Ajoute la gestion des comptes.
  { name = "Session",    run = sessionApp }, -- Ajoute le menu de session.
} -- Termine la liste des applications.

local menu = {} -- Contiendra les applications visibles pour l’utilisateur connecté.

local function buildMenu() -- Déclare la fonction qui construit le menu selon le rôle.
  menu = {} -- Vide le menu avant de le reconstruire.
  for _, app in ipairs(apps) do -- Parcourt toutes les applications enregistrées.
    if not app.admin or session.admin then menu[#menu + 1] = app end -- Ajoute les applications publiques et celles autorisées aux administrateurs.
  end -- Termine le parcours des applications.
end -- Termine la construction du menu.

-- =========================================================
--  Demarrage et bureau
-- =========================================================

local function boot() -- Déclare la fonction qui affiche l’écran de démarrage.
  clear(colors.black, colors.white) -- Efface l’écran avec un fond noir.
  local mid = math.floor(h / 2) -- Calcule la ligne verticale centrale.
  centered(mid - 1, NAME, defaultTheme.accent, colors.black) -- Affiche le nom du système.
  centered(mid, "v" .. VERSION, colors.lightGray, colors.black) -- Affiche le numéro de version.
  local bw = math.min(20, w - 4) -- Définit la largeur de la barre sans dépasser l’espace disponible.
  local x = math.floor((w - bw) / 2) + 1 -- Calcule la colonne où centrer la barre.
  for i = 1, bw do -- Parcourt les segments de la barre de progression.
    writeAt(x + i - 1, mid + 2, " ", colors.white, defaultTheme.accent) -- Dessine un segment de la barre.
    sleep(0.05) -- Attend brièvement pour animer la progression.
  end -- Termine le dessin de la barre de progression.
end -- Termine l’écran de démarrage.

local function showError(name, err) -- Déclare une fonction qui affiche une erreur d’application.
  clear(colors.black, colors.red) -- Efface l’écran en utilisant le rouge pour signaler l’erreur.
  print(name .. " a plante :") -- Affiche le nom de l’application en erreur.
  print() -- Ajoute une ligne vide.
  print(tostring(err)) -- Affiche le détail de l’erreur sous forme de texte.
  print() -- Ajoute une ligne vide avant l’invite.
  print("Appuie sur une touche...") -- Demande à l’utilisateur d’appuyer sur une touche.
  waitKey() -- Attend une touche avant de continuer.
end -- Termine l’affichage de l’erreur.

local function launch(i) -- Déclare la fonction qui lance une application du menu.
  local app = menu[i] -- Récupère l’application correspondant à l’index.
  clear(colors.black, colors.white) -- Efface l’écran avant le lancement.
  local ok, err = pcall(app.run) -- Lance l’application en capturant les erreurs éventuelles.
  -- Ctrl+T dans une appli (mode developpement) = retour au bureau
  if not ok and not tostring(err):find("Terminated") then -- Ignore l’interruption volontaire et détecte les autres erreurs.
    showError(app.name, err) -- Affiche l’erreur associée à l’application.
  end -- Termine le traitement des erreurs.
end -- Termine le lancement d’une application.

local function appRow(i) -- Déclare une fonction qui calcule la ligne d’une application.
  local spacing = (3 + (#menu - 1) * 2 <= h - 2) and 2 or 1 -- Choisit l’espacement selon la hauteur disponible.
  return 3 + (i - 1) * spacing -- Renvoie la ligne associée à l’index de l’application.
end -- Termine le calcul de la ligne.

local function appAt(y) -- Déclare une fonction qui trouve l’application située sur une ligne.
  for i = 1, #menu do -- Parcourt les applications visibles.
    if appRow(i) == y then return i end -- Renvoie l’index si une application se trouve sur la ligne demandée.
  end -- Termine la recherche.
end -- Renvoie nil si aucune application ne se trouve à cette ligne.

local function drawClock() -- Déclare une fonction qui affiche l’heure du jeu sur le bureau.
  local t = string.format(" %5s ", textutils.formatTime(os.time(), true)) -- Formate l’heure et ajoute des espaces autour.
  writeAt(w - #t + 1, 1, t, theme.barText, theme.bar) -- Affiche l’heure à droite de la barre supérieure.
end -- Termine l’affichage de l’heure.

local function drawDesktop() -- Déclare une fonction qui dessine le bureau.
  clear(theme.bg, theme.text) -- Efface l’écran en appliquant les couleurs du thème.
  bar(1, " " .. NAME .. "  " .. session.user .. (session.admin and " [admin]" or ""), -- Prépare le titre avec le nom de l’utilisateur et son rôle.
    theme.barText, theme.bar) -- Affiche le titre avec les couleurs de la barre.
  drawClock() -- Affiche l’heure du jeu.
  for i, app in ipairs(menu) do -- Parcourt les applications visibles.
    local y = appRow(i) -- Calcule la ligne d’affichage de l’application.
    writeAt(3, y, "[" .. i .. "]", theme.accent, theme.bg) -- Affiche le numéro utilisé pour lancer l’application.
    writeAt(7, y, app.name, theme.text, theme.bg) -- Affiche le nom de l’application.
  end -- Termine l’affichage des applications.
  bar(h, " Clic ou touche 1-" .. #menu, theme.barText, theme.bar) -- Affiche les moyens de sélectionner une application.
end -- Termine le dessin du bureau.

-- Renvoie "logout" ou "exit"
local function desktop() -- Déclare la boucle principale du bureau et de ses événements.
  local lastActivity = os.clock() -- Mémorise le moment de la dernière activité.
  while true do -- Répète l’affichage et le traitement du bureau.
    drawDesktop() -- Dessine le bureau avant d’attendre une action.
    local timer = os.startTimer(1) -- Démarre un minuteur pour actualiser l’heure chaque seconde.
    local redraw = false -- Indique qu’il n’est pas encore nécessaire de redessiner le bureau.
    while not redraw do -- Traite les événements jusqu’à ce qu’un nouveau dessin soit requis.
      local ev, a, b, c = pullEvent() -- Récupère un événement et ses paramètres.
      local i = nil -- Initialise l’index de l’application éventuellement sélectionnée.
      if ev == "timer" and a == timer then -- Vérifie si le minuteur d’actualisation de l’heure a expiré.
        drawClock() -- Met à jour l’heure affichée.
        timer = os.startTimer(1) -- Démarre le minuteur de la seconde suivante.
        if AUTOLOCK > 0 and os.clock() - lastActivity > AUTOLOCK then -- Vérifie si le délai de verrouillage automatique est dépassé.
          lockScreen() -- Verrouille la session après la période d’inactivité.
          lastActivity = os.clock() -- Réinitialise le moment de la dernière activité après le déverrouillage.
          redraw = true -- Demande de redessiner le bureau.
        end -- Termine la vérification du verrouillage automatique.
      elseif ev == "mouse_click" then -- Traite un clic de souris.
        lastActivity = os.clock() -- Enregistre l’activité de l’utilisateur.
        i = appAt(c) -- Cherche l’application située sur la ligne cliquée.
      elseif ev == "char" then -- Traite une touche de caractère.
        lastActivity = os.clock() -- Enregistre l’activité de l’utilisateur.
        i = tonumber(a) -- Convertit le caractère en numéro d’application.
        if i and not menu[i] then i = nil end -- Ignore les numéros qui ne correspondent à aucune application visible.
      elseif ev == "term_resize" then -- Traite un changement de taille du terminal.
        w, h = term.getSize() -- Met à jour les dimensions de l’écran.
        redraw = true -- Demande de redessiner le bureau selon la nouvelle taille.
      end -- Termine le traitement de l’événement courant.

      if i then -- Vérifie si une application a été sélectionnée.
        launch(i) -- Lance l’application correspondante.
        lastActivity = os.clock() -- Enregistre l’activité après le retour de l’application.
        if pendingAction then -- Vérifie si l’application a demandé une action de session.
          local action = pendingAction -- Copie l’action demandée.
          pendingAction = nil -- Efface l’action en attente pour éviter de la répéter.
          return action -- Renvoie l’action à la boucle de session.
        end -- Termine le traitement de l’action en attente.
        redraw = true -- Demande de redessiner le bureau après l’application.
      end -- Termine le traitement de la sélection d’application.
    end -- Termine la boucle de traitement des événements.
  end -- Termine la boucle du bureau.
end -- Termine la fonction du bureau.

-- Boucle de sessions : connexion -> bureau -> deconnexion -> connexion...
-- Ne se termine que si un administrateur choisit "Quitter vers CraftOS".
local function sessionLoop() -- Déclare la boucle qui gère les connexions successives.
  while true do -- Répète les sessions jusqu’à la sortie vers CraftOS.
    if userCount() == 0 then setupScreen() end -- Lance la première installation si aucun compte n’existe.
    local rec, pw = loginScreen() -- Demande à l’utilisateur de se connecter.
    session = { user = rec.name, admin = rec.admin, pw = pw, home = fs.combine(HOME_ROOT, rec.name) } -- Crée la session avec le compte, son rôle et son dossier personnel.
    if not fs.exists(session.home) then fs.makeDir(session.home) end -- Crée le dossier personnel s’il n’existe pas.
    loadSettings() -- Charge le thème associé à l’utilisateur.
    buildMenu() -- Construit le menu adapté au rôle de l’utilisateur.
    local action = desktop() -- Lance le bureau et récupère l’action demandée à la fin.
    session = nil   -- le mot de passe en memoire disparait ici -- Efface la session et son mot de passe de la mémoire.
    resetTheme() -- Restaure le thème par défaut avant la prochaine session.
    if action == "exit" then return end -- Quitte MiniOS si l’administrateur a demandé la sortie vers CraftOS.
  end -- Termine la boucle des sessions.
end -- Termine la gestion des sessions.

loadUsers() -- Charge les comptes enregistrés sur l’ordinateur.
boot() -- Affiche l’écran de démarrage avant les connexions.

while true do -- Protège la boucle de sessions et permet de récupérer après une erreur.
  local ok, err = pcall(sessionLoop) -- Lance la boucle de sessions en capturant les erreurs.
  if ok then break end -- Quitte cette boucle si MiniOS s’est terminé sans erreur.
  if not KIOSK then error(err, 0) end -- En mode développement, propage l’erreur au système.
  session = nil -- Efface les données de session après une erreur.
  resetTheme() -- Restaure le thème par défaut après une erreur.
  showError(NAME, err) -- Affiche l’erreur et attend une touche avant de reprendre.
end -- Termine la boucle de récupération après erreur.

clear(colors.black, colors.white) -- Efface l’écran à la fermeture de MiniOS.
print(NAME .. " ferme. A bientot !") -- Affiche le message final.