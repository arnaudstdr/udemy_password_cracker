#!/usr/bin/env pyt
import time
import string
import hashlib
import sys
import argparse
import atexit
import urllib.request
import urllib.error

def crak_dict(md5, file):
    try:
        trouve = False
        ofile = open(file, "r")
        for mot in ofile.readlines():
            mot = mot.strip("\n")
            hashmd5 = hashlib.md5(mot.encode("utf8")).hexdigest()
            if hashmd5 == md5:
                print("Mot de passe trouvé : " + str(mot) + " (" + hashmd5 + ")")
                trouve = True
        if not trouve:
            print("Mot de passe non trouvé :")
        ofile.close()
    except FileNotFoundError:
        print("Erreur : nom de dossier ou fichier introuvable !")
        sys.exit(1)
    except Exception as err:
        print("Erreur : " + str(err))
        sys.exit(2)


def crack_incr(md5, length, currpass=[]):
    lettres = string.printable

    if length >=1:
        if len(currpass) == 0:
            currpass = ['a' for _ in range(length)]
            crack_incr(md5, length, currpass)
        else:
            for c in lettres:
                currpass[length - 1] = c
                print("Trying : " + "".join(currpass))
                if hashlib.md5("".join(currpass).encode("utf8")).hexdigest() == md5:
                    print("PASSWORD FOUND !" + "".join(currpass))
                    sys.exit(0)
                else:
                    crack_incr(md5, length - 1, currpass)


def crack_en_ligne(md5):
    try:
        agent_utilisateur = "Mozilla/5.0 (Windows; U; Windows NT 5.1; fr-FR; rv:1.9.0.7) Gecko/2009021910 Firefox/3.0.7"
        headers = {'User-Agent': agent_utilisateur}
        url = "https://www.google.fr/search?hl=fr&q=" +md5
        requete = urllib.request.Request(url, None, headers)
        reponse = urllib.request.urlopen(requete)
    except urllib.error.HTTPError as e:
        print("Erreur HTTP : " + e.code)
    except urllib.error.URLError as e:
        print("Erreur d'URL : " + e.reason)

    if "Aucun document" in str(reponse.read()):
        print("[-] HASH NON TROUVE VIA GOOGLE")
    else:
        print("[+] MOT DE PASSE TROUVE VIA GOOGLE : " + url)

def display_name():
    print("Durée : " + str(time.time() - debut) + "secondes")


parser = argparse.ArgumentParser(description="Password Cracker")
parser.add_argument("-f", "--file", dest="file", help="Path oh the dictionary file", required=False)
parser.add_argument("-g", "--gen", dest="gen", help="Generate MD5 hash password", required=False)
parser.add_argument("-md5", dest="md5", help="Hashed password", required=False)
parser.add_argument("-l", dest="plength", help="Password length", required=False, type=int)
parser.add_argument("-o", dest="online", help="Cherche le hash e  ligne (google", required=False, action="store_true")

args = parser.parse_args()

debut = time.time()
atexit.register(display_name)
if args.md5:
    print("[CRACKIN HASH" + args.md5 + "]")
    if args.file and not args.plength:
        print("[USING DICTIONARY FILE" + args.file + "]")
        crak_dict(args.md5, args.file)
    elif args.plength and not args.file:
        print("USING INCREMENTAL MODE FOR " + str(args.plength) + "letters(s)")
        crack_incr(args.md5, args.plength)
    elif args.online:
        print("[*] UTILISANT LE MODE EN LIGNE")
        crack_en_ligne(args.md5)
    else:
        print("Please choose either -f or -l argument")
else:
    print("MD5 hash not provided")

if args.gen:
    print("[MD5 HASH OF " + args.gen + " : " + hashlib.md5(args.gen.encode("utf8")).hexdigest())