# Cyber Security in der Praxis🤯

## Einleitung
In diesem ePortfolio werde ich anhand von Artefakten meine Zielerreichung der jeweiligen Handlungsziele vorzeigen und erklären. Mit hilfe der Insecure-App des Moduls 183 konnte ich Sicherheitslücken suchen, erkennen und beheben, was mir viel Spass bereitete. 


## 🎯Handlungsziel 1
Aktuelle Bedrohungen erkennen und erläutern können. Aktuelle Informationen zum Thema (Erkennung und Gegenmassnahmen) beschaffen und mögliche Auswirkungen aufzeigen und erklären können.

### Artefakt
![image](https://github.com/karakushi/KarakushiYlliLB-183/assets/118426881/df6418ed-c587-4d9e-a7d4-c12c27f41de7)

**Erkennungsmethoden**
- ***DDoS-Attacke:***
  - Überwachung von Netzwerkverkehr 
  - Einsatz von DDoS-Schutzdiensten und -Tools 

- ***Phishing:***
  - Überprüfung von E-Mails und URLs
  - Schulung von Benutzern zur Erkennung von Phishing-Versuchen

- ***Netzwerkprotokollierung durch Angreifer:***
  - Überwachung von Netzwerkprotokollen
  - Einsatz von Intrusion Detection Systems (IDS)

- ***Veränderung von Daten in einer Datenbank:***
  - Implementierung von Datenbank-Audit-Trail-Mechanismen
  - Überwachung von Datenbankaktivitäten und -transaktionen.

- ***XSS-Angriff:***
  - Überprüfung von Benutzereingaben
  - Implementierung von Content Security Policy (CSP) und Input Validation

### Zielerreichung
Mit der oben abgebildeten Aufgabe, welche ich während dem Unterricht gelöst habe, konnte ich Szenarien den drei Schutzzielen zuordnen bzw. welche wie stark betroffen sind. Ebenfalls weiss ich durch den Erkennungsmethoden nun, wie ich Angriffe verhindern kann.

### Erklärung
Die Erkennungsmethoden sind

### Rückblick
Durch einen Auftrag, den wir im Modul 183 zusammen im Modulunterricht an der BBBaden gelöst haben, konnte ich viele wertvolle Informationen in meinen Wissensrucksack packen🧠🎒. Es war kein schwieriger jedoch ein leseaufwendiger Auftrag. Trotz allem bin ich nun fit was aktuelle Bedrohungen und ihre Auswirkungen angeht.

## 🎯Handlungsziel 2
Sicherheitslücken und ihre Ursachen in einer Applikation erkennen können. Gegenmassnahmen vorschlagen und implementieren können.

### Artefakte
![image](https://github.com/karakushi/KarakushiYlliLB-183/assets/118426881/6269e8ab-797b-4cef-b57d-a05a62f78fae)

![image](https://github.com/karakushi/KarakushiYlliLB-183/assets/118426881/d0b45e34-2ebe-4386-8734-6cb66f80b776)


### Zielerreichung
Dieses Ziel habe ich erreicht indem ich den Code vom Bild 1 zu einer parameterisierten Abfrage abgeändert habe. Wie auf Bild 2 zu erkennen ist.

### Erklärung
Um SQL-Injektionen zu verhindern, ist es wichtig, parameterisierte Abfragen zu verwende, da sonst Leute mit bösen Absichten meine Datenbank durcheinander bringen können mit sehr einfachen Injektionen. Das will doch keiner.  
Was sind nun parameterisierte Abfragen?
Anstatt dass es einen direkten Kontakt zwischen dem Nutzer und der Datenbank gibt soll bei der parameterisierten Abfrage noch etwas dazwischen sein; ein Platzhalter oder ein Parameter. Diese verhindern das Risiko von Injektionen stark.

### Rückblick
Natürlich könnte das Programm weiter verbessert werden indem ich zum Beispiel noch salt-hashing hinzufüge. Jedoch bin ich mit dem Ergebnis relativ zufrieden da ich das Ziel erreicht habe indem ich eine Sicherheitslücke entdeckt habe und diese behoben habe.

## 🎯Handlungsziel 3
Mechanismen für die Authentifizierung und Autorisierung umsetzen können.

### Artefakt
```C#
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

[HttpPost]
public ActionResult Login(LoginDto request)
{
    if (request == null || string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
    {
        return BadRequest();
    }

    var user = _context.Users.FirstOrDefault(u => u.Username == request.Username && u.Password == MD5Helper.ComputeMD5Hash(request.Password));

    if (user == null)
    {
        return Unauthorized();
    }

    var tokenHandler = new JwtSecurityTokenHandler();
    var key = Encoding.ASCII.GetBytes("IhrGeheimerSchlüsselHier"); // Stellen Sie sicher, dass Sie Ihren geheimen Schlüssel sicher speichern
    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new Claim[] 
        {
            new Claim(ClaimTypes.Name, user.Username)
        }),
        Expires = DateTime.UtcNow.AddDays(7),
        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
    };

    var token = tokenHandler.CreateToken(tokenDescriptor);
    var tokenString = tokenHandler.WriteToken(token);

    // Rückgabe des Tokens
    return Ok(new { Token = tokenString });
}
```

### Zielerreichung
Da ich verstehe was JWT-Tokens sind und wie man diese zur Authentifizierung und Autorisierung, wie im obigen Code, anwendet, habe ich das Ziel erreicht.

### Erklärung
***Authentifizierung*** 
Die Authentifizierung erfolgt, indem überprüft wird, ob die Kombination aus Benutzername und Passwort in der Datenbank existiert.

***JWT-Token-Erstellung***
Bei erfolgreicher Authentifizierung wird ein JWT-Token erstellt. Dieses Token enthält Claims, ein Ablaufdatum und wird mit einem geheimen Schlüssel signiert.

***Token-Rückgabe*** 
Das erstellte Token wird dann an den Benutzer zurückgegeben.

***Autorisierung***
Die Autorisierung kann durch das Überprüfen der Claims im Token erfolgen.

### Rückblick
Ich hatte Probleme das zu Beginn mir in den Kopf einzuprägen, jedoch macht Übung den Meister und ich konnte schlussendlich meine eigene Authentifizierung und Autorisierung in die InsecureApp einbauen.

## 🎯Handlungsziel 4
Sicherheitsrelevante Aspekte bei Entwurf, Implementierung und Inbetriebnahme berücksichtigen.

### Artefakt

### Zielerreichung

### Erklärung

### Rückblick


## 🎯Handlungsziel 5
Informationen für Auditing und Logging generieren. Auswertungen und Alarme definieren und implementieren.

### Artefakt

### Zielerreichung

### Erklärung

### Rückblick
