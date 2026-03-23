# scorer.py — risk score calculation
import re
import difflib
from urllib.parse import urlparse

WHITELIST = [
    # Indian Banking
    'onlinesbi.sbi', 'sbi.co.in', 'sbi.bank.in', 'onlinesbi.sbi.bank.in',
    'hdfcbank.com', 'icicibank.com', 'axisbank.com', 'kotak.com',
    'bankofbaroda.in', 'pnbindia.in', 'canarabank.com', 'unionbankofindia.co.in',
    'yesbank.in', 'indusind.com', 'federalbank.co.in', 'idfcfirstbank.com',

    # Indian Payments
    'paytm.com', 'phonepe.com', 'mobikwik.com', 'bhimupi.org.in',
    'npci.org.in', 'upi.one',

    # Global Tech
    'google.com', 'gmail.com', 'google.co.in', 'google.co.uk',
    'youtube.com', 'youtu.be',
    'microsoft.com', 'live.com', 'outlook.com', 'office.com', 'microsoft365.com',
    'apple.com', 'icloud.com',
    'amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.de', 'amazon.co.jp',
    'aws.amazon.com', 'amazonaws.com',

    # Social Media
    'facebook.com', 'fb.com', 'messenger.com',
    'instagram.com',
    'twitter.com', 'x.com',
    'linkedin.com',
    'pinterest.com',
    'snapchat.com',
    'tiktok.com',
    'discord.com', 'discordapp.com',
    'reddit.com', 'redd.it',
    'tumblr.com',
    'quora.com',
    'threads.net',

    # Messaging
    'whatsapp.com', 'web.whatsapp.com',
    'telegram.org', 'web.telegram.org',
    'signal.org',
    'zoom.us', 'zoom.com',
    'meet.google.com',
    'teams.microsoft.com',
    'slack.com',
    'skype.com',

    # Streaming
    'netflix.com',
    'spotify.com',
    'hotstar.com', 'disneyplus.com',
    'primevideo.com',
    'hulu.com',
    'twitch.tv',
    'vimeo.com',
    'dailymotion.com',
    'soundcloud.com',
    'music.apple.com',
    'music.youtube.com',

    # Developer / Tech
    'github.com', 'githubusercontent.com', 'github.io',
    'gitlab.com',
    'bitbucket.org',
    'stackoverflow.com', 'stackexchange.com', 'superuser.com', 'serverfault.com',
    'npmjs.com',
    'pypi.org',
    'docker.com', 'hub.docker.com',
    'heroku.com',
    'vercel.app', 'vercel.com',
    'netlify.app', 'netlify.com',
    'replit.com',
    'codepen.io',
    'codesandbox.io',
    'jsfiddle.net',
    'medium.com',
    'dev.to',
    'hashnode.dev',
    'digitalocean.com',
    'cloudflare.com',
    'firebase.google.com',
    'cloud.google.com',
    'azure.microsoft.com',
    'portal.azure.com',

    # Search Engines
    'bing.com',
    'duckduckgo.com',
    'yahoo.com', 'yahoo.co.in',
    'baidu.com',
    'ecosia.org',
    'brave.com',

    # Indian E-commerce
    'flipkart.com',
    'myntra.com',
    'nykaa.com',
    'meesho.com',
    'snapdeal.com',
    'ajio.com',
    'tatacliq.com',
    'bigbasket.com',
    'grofers.com', 'blinkit.com',
    'jiomart.com',
    'reliancedigital.in',
    'croma.com',
    'vijaysales.com',

    # Global E-commerce / Finance
    'paypal.com',
    'stripe.com',
    'razorpay.com',
    'ebay.com',
    'etsy.com',
    'aliexpress.com',
    'shopify.com',
    'walmart.com',
    'target.com',

    # Food Delivery
    'zomato.com',
    'swiggy.com',
    'dominos.co.in', 'dominos.com',
    'mcdonalds.com',

    # Travel
    'irctc.co.in', 'irctc.com',
    'makemytrip.com',
    'goibibo.com',
    'cleartrip.com',
    'yatra.com',
    'booking.com',
    'airbnb.com',
    'expedia.com',
    'skyscanner.com', 'skyscanner.net',
    'indigo.in', 'goindigo.in',
    'airindia.in',

    # News
    'bbc.com', 'bbc.co.uk',
    'cnn.com',
    'reuters.com',
    'theguardian.com',
    'nytimes.com',
    'thehindu.com',
    'hindustantimes.com',
    'ndtv.com',
    'timesofindia.com', 'indiatimes.com',
    'indianexpress.com',
    'livemint.com',
    'economictimes.com',
    'moneycontrol.com',
    'businessstandard.com',

    # Education
    'wikipedia.org', 'wikimedia.org',
    'khanacademy.org',
    'coursera.org',
    'udemy.com',
    'edx.org',
    'nptel.ac.in',
    'swayam.gov.in',
    'brilliant.org',
    'duolingo.com',
    'geeksforgeeks.org',
    'w3schools.com',
    'tutorialspoint.com',
    'leetcode.com',
    'hackerrank.com',
    'codeforces.com',

    # Indian Government
    'uidai.gov.in',
    'incometax.gov.in',
    'india.gov.in',
    'mygov.in',
    'makeinindia.com',
    'digilocker.gov.in',
    'epfindia.gov.in',
    'esic.in',
    'mca.gov.in',
    'gst.gov.in',
    'sebi.gov.in',
    'rbi.org.in',
    'irdai.gov.in',
    'passportindia.gov.in',

    # Productivity / Cloud
    'drive.google.com', 'docs.google.com', 'sheets.google.com', 'forms.google.com',
    'notion.so',
    'trello.com',
    'atlassian.com', 'jira.atlassian.com',
    'dropbox.com',
    'box.com',
    'evernote.com',
    'airtable.com',
    'figma.com',
    'canva.com',
    'adobe.com',

    # Security
    'norton.com', 'mcafee.com', 'kaspersky.com',
    'avast.com', 'avg.com', 'malwarebytes.com', 'virustotal.com',

    # AI Tools
    'openai.com', 'chatgpt.com',
    'anthropic.com', 'claude.ai',
    'gemini.google.com',
    'wolframalpha.com',

    # Misc
    'archive.org', 'imdb.com',
    'cricbuzz.com', 'espncricinfo.com',
    'chess.com', 'lichess.org',
    'waze.com',
    'ola.com', 'olacabs.com',
    'uber.com',
    'rapido.bike',
]

BRANDS = [
    'google', 'gmail', 'youtube',
    'facebook', 'instagram', 'whatsapp', 'messenger',
    'twitter', 'x',
    'amazon', 'aws',
    'apple', 'icloud',
    'microsoft', 'outlook', 'office', 'azure',
    'paypal', 'stripe', 'razorpay',
    'netflix', 'spotify', 'hotstar', 'disney',
    'linkedin', 'pinterest', 'snapchat', 'tiktok', 'discord', 'reddit',
    'github', 'gitlab',
    'zoom', 'slack', 'teams',
    'dropbox', 'notion', 'figma', 'canva', 'adobe',
    'sbi', 'hdfc', 'icici', 'axis', 'kotak', 'paytm', 'phonepe',
    'flipkart', 'myntra', 'zomato', 'swiggy', 'nykaa', 'meesho',
    'irctc', 'makemytrip', 'goibibo',
    'openai', 'chatgpt', 'anthropic', 'claude',
    'norton', 'mcafee', 'kaspersky',
    'ebay', 'etsy', 'shopify', 'walmart',
    'booking', 'airbnb', 'expedia',
    'uber', 'ola',
]

# -----------------------------------------------------------------------
# TYPOSQUAT DATABASE — maps fake domains → real site
# -----------------------------------------------------------------------
TYPOSQUATS = {

    # ── GitHub ──
    'github.com': [
        'guthi.com', 'githb.com', 'gihub.com', 'githubb.com', 'githup.com',
        'gitub.com', 'gihtub.com', 'github.co', 'github.cm', 'github.om',
        'gthub.com', 'gtihub.com', 'giithub.com', 'githubs.com', 'ghithub.com',
        'githubcom.com', 'guthib.com', 'gitbub.com', 'gihub.com', 'githib.com',
        'githhub.com', 'githubc.om', 'git-hub.com', 'gi-thub.com', 'githube.com',
        'githuub.com', 'girhub.com', 'giltub.com', 'githuv.com', 'githug.com',
        'githubn.com', 'gitgub.com', 'githob.com', 'githab.com', 'githoob.com',
        'githuba.com', 'githubd.com', 'githubi.com', 'guthub.com', 'gethub.com',
    ],

    # ── Google ──
    'google.com': [
        'gogle.com', 'googl.com', 'gooogle.com', 'googie.com', 'g00gle.com',
        'goggle.com', 'googlr.com', 'goolge.com', 'gogle.com', 'googlle.com',
        'googel.com', 'gogle.net', 'googlw.com', 'googles.com', 'googs.com',
        'googlee.com', 'goog1e.com', 'g0ogle.com', 'googlc.com', 'giogle.com',
        'gpogle.com', 'goigle.com', 'googe.com', 'ggoogle.com', 'googled.com',
        'googl3.com', 'g00g1e.com', 'googie.net', 'gooogle.net', 'google.cm',
        'google.co', 'google.om', 'googlw.com', 'goog.com', 'googlr.net',
    ],

    # ── Gmail ──
    'gmail.com': [
        'gmai.com', 'gmal.com', 'gmial.com', 'gmaill.com', 'gmai1.com',
        'gmali.com', 'gmaill.net', 'gmil.com', 'gmaol.com', 'gmaill.com',
        'gnail.com', 'gmailcom.com', 'gmail.co', 'gmail.cm', 'gmai1l.com',
        'g-mail.com', 'gmaill.org', 'gmaie.com', 'gmail.om', 'gmails.com',
    ],

    # ── YouTube ──
    'youtube.com': [
        'youttube.com', 'youtub.com', 'yutube.com', 'youtobe.com', 'youtubee.com',
        'youtueb.com', 'yootube.com', 'youtue.com', 'y0utube.com', 'youtub3.com',
        'youtubbe.com', 'yputube.com', 'uoutube.com', 'youtuge.com', 'yiutube.com',
        'youtuhe.com', 'youttbe.com', 'yotube.com', 'youtubr.com', 'youtube.co',
        'youtube.cm', 'you-tube.com', 'youtubs.com', 'youtude.com', 'youtubes.com',
        'yt.com.co', 'youtube.om', 'yuotube.com', 'youtubc.com', 'yout-ube.com',
    ],

    # ── Facebook ──
    'facebook.com': [
        'faceb00k.com', 'facebok.com', 'faceboook.com', 'facebock.com', 'facbook.com',
        'fcaebook.com', 'faceebook.com', 'facbook.net', 'faecbook.com', 'facebbok.com',
        'faceboock.com', 'faceook.com', 'fac3book.com', 'faceb0ok.com', 'facebok.net',
        'faceboo.com', 'facebokk.com', 'faceboook.net', 'facebook.cm', 'facebook.co',
        'face-book.com', 'facebookk.com', 'fcebook.com', 'facebok.org', 'facebok.in',
        'faceb0ok.net', 'facebook.om', 'faceook.net', 'facebool.com', 'facepook.com',
    ],

    # ── Instagram ──
    'instagram.com': [
        'instagran.com', 'instagrarn.com', 'instagam.com', 'instragram.com',
        'instgram.com', 'instagrm.com', 'insagram.com', 'instagrame.com',
        'instgaram.com', 'instaragram.com', 'instagrama.com', 'instagramm.com',
        'in5tagram.com', 'instagrarn.net', 'instagram.co', 'instagram.cm',
        'insatgram.com', 'instagr4m.com', 'instagram.net', 'lnstagram.com',
        'iinstagram.com', 'instaagram.com', 'instagramcom.com', 'inst4gram.com',
    ],

    # ── Twitter / X ──
    'twitter.com': [
        'twiter.com', 'twtter.com', 'twittter.com', 'twiiter.com', 'twitterr.com',
        'twitte.com', 'twittr.com', 'twitteer.com', 'twitter.co', 'twitter.cm',
        'twiter.net', 'twittter.net', 'twittercom.com', 'tw1tter.com', 'twltter.com',
        'twiitter.com', 'tvvitter.com', 'twwitter.com', 'twitter.om', 'twittere.com',
    ],

    # ── LinkedIn ──
    'linkedin.com': [
        'linkedln.com', 'linkedn.com', 'linkin.com', 'linkediin.com', 'linke-in.com',
        'linkdin.com', 'linkeden.com', 'linkedln.net', 'linkendin.com', 'linkiedin.com',
        'linkedin.co', 'linkedin.cm', 'linkedinn.com', 'linkekin.com', 'lindkedin.com',
        'linkedincom.com', 'llinkedin.com', 'linlkedin.com', 'linkedln.org', 'linkin.net',
    ],

    # ── Amazon ──
    'amazon.com': [
        'amaz0n.com', 'amazom.com', 'amazoon.com', 'arnazon.com', 'anazon.com',
        'amzon.com', 'amazn.com', 'amozon.com', 'amazom.net', 'amazone.com',
        'amazzon.com', 'amaz0n.net', 'amazin.com', 'amason.com', 'amazon.co',
        'amazon.cm', 'amazan.com', 'amazob.com', 'amazkn.com', 'amaz-on.com',
        'amazonn.com', 'amazpon.com', 'amzaon.com', 'amazaon.com', 'amazlon.com',
        'amazone.net', 'amazon.om', 'amzon.net', 'amazzon.net', 'amazun.com',
    ],

    'amazon.in': [
        'amaz0n.in', 'amazom.in', 'amazoon.in', 'amzon.in', 'amazone.in',
        'amazin.in', 'amason.in', 'amazan.in', 'amazon.i', 'amazonn.in',
    ],

    # ── PayPal ──
    'paypal.com': [
        'paypa1.com', 'paypai.com', 'paypall.com', 'payp4l.com', 'paipal.com',
        'paypl.com', 'paypol.com', 'pay-pal.com', 'paypal.co', 'paypal.cm',
        'paypall.net', 'paypa1.net', 'paypal.om', 'paypale.com', 'paypall.org',
        'papyal.com', 'paypaal.com', 'paypalll.com', 'paypa.com', 'ppaypal.com',
    ],

    # ── Netflix ──
    'netflix.com': [
        'netfl1x.com', 'netfilx.com', 'netflex.com', 'netlfix.com', 'n3tflix.com',
        'netf1ix.com', 'netfliix.com', 'netflixs.com', 'netflix.co', 'netflix.cm',
        'netflx.com', 'netfl1x.net', 'net-flix.com', 'nettflix.com', 'netfflix.com',
        'netflicks.com', 'netlix.com', 'netfli.com', 'neflix.com', 'netflix.om',
    ],

    # ── Spotify ──
    'spotify.com': [
        'sport1fy.com', 'sportify.com', 'spotfy.com', 'spotifY.com', 'sp0tify.com',
        'spotify.co', 'spotifyy.com', 'spottify.com', 'spotifiy.com', 'spotif.com',
        'spotift.com', 'spotfiy.com', 'spotiify.com', 'spotify.cm', 'spotify.om',
        'spotidy.com', 'spotifys.com', 'spotyfy.com', 'spooify.com', 'spotiffy.com',
    ],

    # ── Microsoft ──
    'microsoft.com': [
        'micros0ft.com', 'microsft.com', 'mircosoft.com', 'microsodt.com',
        'microsoftt.com', 'mircrosoft.com', 'microsfot.com', 'microsoft.co',
        'microsoft.cm', 'm1crosoft.com', 'micr0soft.com', 'microsoff.com',
        'micsoroft.com', 'microsot.com', 'microsoft.om', 'micosoft.com',
        'microosft.com', 'microsoftcom.com', 'microsofr.com', 'mikerosoft.com',
    ],

    # ── Apple ──
    'apple.com': [
        'appl3.com', 'aple.com', 'applee.com', 'aplle.com', 'appl.com',
        'apple.co', 'apple.cm', 'apple.om', 'apples.com', 'appile.com',
        'appl3.net', 'aplpe.com', 'appple.com', 'appel.com', 'apple-inc.com',
        'appleinc.com', 'app1e.com', 'aapple.com', 'applacom.com', 'appie.com',
    ],

    # ── WhatsApp ──
    'whatsapp.com': [
        'whatsap.com', 'whatssapp.com', 'watsapp.com', 'whatsappp.com',
        'whats-app.com', 'whatsaap.com', 'wwhatsapp.com', 'whatsapp.co',
        'whatsapp.cm', 'whatapp.com', 'whatsap.net', 'whatsapp.om',
        'whataspp.com', 'whtsapp.com', 'whatsapp.net', 'whatsapps.com',
        'wahtsapp.com', 'whatasap.com', 'whatsapp.org', 'watsap.com',
    ],

    # ── Flipkart ──
    'flipkart.com': [
        'fl1pkart.com', 'flickart.com', 'flipkart.co', 'fipkart.com',
        'flipkart.in', 'flipk4rt.com', 'fliipkart.com', 'flipkarrt.com',
        'flip-kart.com', 'flipcart.com', 'flipkart.cm', 'f1ipkart.com',
        'flipkartz.com', 'fliokart.com', 'flipkartt.com', 'flikpart.com',
        'flipkart.om', 'flipkat.com', 'flipkert.com', 'flipkard.com',
    ],

    # ── Paytm ──
    'paytm.com': [
        'paytrn.com', 'paytm.co', 'paitm.com', 'paytm.in', 'pa1tm.com',
        'paytmm.com', 'paytim.com', 'patyim.com', 'paymt.com', 'p4ytm.com',
        'paytm.cm', 'paytm.om', 'patym.com', 'paytem.com', 'paaytm.com',
    ],

    # ── PhonePe ──
    'phonepe.com': [
        'ph0nepe.com', 'phonep3.com', 'phone-pe.com', 'phonepe.co',
        'phoneep.com', 'phon3pe.com', 'phonepe.in', 'phonppe.com',
        'phoneepe.com', 'phonpee.com', 'fonepe.com', 'phonepe.cm',
    ],

    # ── SBI ──
    'onlinesbi.sbi': [
        'onlinesbi.com', 'online-sbi.com', 'sbi-online.com', 'onlinesbi.co',
        'onlinesbi.net', 'onlinesbi.in', 'onlinesbi.org', 'sbionline.com',
        'onlinesbi.sbi.co', 'sbionlne.com', 'sbi-netbanking.com',
        'onlinesbi.com.in', 'sbionline.in', 'sbiinternet.com',
    ],

    # ── HDFC Bank ──
    'hdfcbank.com': [
        'hdfcban.com', 'hdfcbnak.com', 'hdfcbankk.com', 'hdfc-bank.com',
        'hdfbank.com', 'hdfcbanknet.com', 'hdfcbnk.com', 'hdfcbonk.com',
        'hdfcbank.co', 'hdfcbank.in', 'hdfc-netbanking.com', 'hdfcbankk.in',
    ],

    # ── ICICI Bank ──
    'icicibank.com': [
        'icicibnak.com', 'icici-bank.com', 'icicibnk.com', 'icicibankk.com',
        'icicibank.co', 'icicibank.in', 'icici-netbanking.com', 'icicbank.com',
        'iciciibank.com', 'icicibank.net', 'icic1bank.com', 'icicibanl.com',
    ],

    # ── Discord ──
    'discord.com': [
        'discrod.com', 'discordd.com', 'discor.com', 'disc0rd.com', 'doscord.com',
        'discorrd.com', 'disscord.com', 'discord.co', 'discord.gg.com',
        'discords.com', 'discordapp.co', 'discorde.com', 'dicord.com',
        'disc0rd.net', 'discard.com', 'discorrd.net', 'discord.cm',
    ],

    # ── Reddit ──
    'reddit.com': [
        'reddt.com', 'reddlt.com', 'reddlt.net', 'rediit.com', 'reditt.com',
        'reddit.co', 'reddlt.com', 'r3ddit.com', 'reddi.com', 'reddlt.org',
        'redditt.com', 'redit.com', 'reddit.cm', 'readit.com', 'reddit.om',
        'reddot.com', 'reddlt.com', 'reddlt.net', 'reditit.com', 'reeddit.com',
    ],

    # ── Snapchat ──
    'snapchat.com': [
        'snapcht.com', 'snapcat.com', 'snpachat.com', 'snapchatt.com',
        'snap-chat.com', 'snapchat.co', 'snaapChat.com', 'snapchta.com',
        'snapchat.cm', 'snapchats.com', 'snapchet.com', 'snaochat.com',
    ],

    # ── TikTok ──
    'tiktok.com': [
        'tiktk.com', 'tictok.com', 'tik-tok.com', 'tikttok.com', 'tiktok.co',
        'tiktokk.com', 'tikok.com', 'tiktok.com', 'tiktob.com', 'tiktok.cm',
        'tic-tok.com', 'tiltok.com', 'tiitok.com', 'tik0tok.com', 'tiktok.om',
    ],

    # ── Pinterest ──
    'pinterest.com': [
        'pintrest.com', 'pinterst.com', 'pininterest.com', 'pinterrest.com',
        'pintrest.net', 'pinterest.co', 'pinteresst.com', 'pinteres.com',
        'pinterest.cm', 'pintetest.com', 'pintreset.com', 'pinerest.com',
    ],

    # ── Zoom ──
    'zoom.us': [
        'zoom.com', 'zo0m.us', 'z0om.us', 'zooom.us', 'zoom.co',
        'zoom-us.com', 'zoomm.us', 'zomm.us', 'zooom.com', 'zoom.net',
        'zoom.cm', 'z00m.com', 'zoim.us', 'zoom.in', 'zoommeeting.com',
    ],

    # ── Slack ──
    'slack.com': [
        'sl4ck.com', 'slaack.com', 'slakk.com', 'slac.com', 'slacck.com',
        'slack.co', 'slack.cm', 'sllack.com', 'slak.com', 'sla ck.com',
        'slack.net', 'slack.om', 'slacks.com', 'slck.com', 'slack-app.com',
    ],

    # ── Telegram ──
    'telegram.org': [
        'telgram.org', 'telegam.org', 'telegramm.org', 'teligram.org',
        'telegram.com', 'telegram.co', 'tele-gram.org', 'telagram.org',
        'telegramm.com', 'telegran.org', 'telegramorg.com', 'telegran.com',
        'tel3gram.org', 'telgram.com', 'telegram.net', 'teiegram.org',
    ],

    # ── Dropbox ──
    'dropbox.com': [
        'dr0pbox.com', 'dropb0x.com', 'dropboxx.com', 'deopbox.com',
        'dropox.com', 'drop-box.com', 'droopbox.com', 'dropbox.co',
        'dropbox.cm', 'dropbpx.com', 'dropboxs.com', 'drpbox.com',
        'dropbxo.com', 'dropbix.com', 'dropbox.om', 'drobpox.com',
    ],

    # ── Notion ──
    'notion.so': [
        'notion.com', 'notlon.so', 'noton.so', 'noti0n.so', 'not1on.so',
        'notion.co', 'notiion.so', 'notoon.so', 'notion.net', 'notion.cm',
        'n0tion.so', 'noition.so', 'notionn.so', 'notions.com', 'notoon.com',
    ],

    # ── GitHub GitLab ──
    'gitlab.com': [
        'gitlabb.com', 'gitab.com', 'git-lab.com', 'gltlab.com', 'gitlaab.com',
        'gitlob.com', 'gitlabcom.com', 'gitlab.co', 'gitlab.cm', 'gilab.com',
        'gitlav.com', 'gittlab.com', 'gitlag.com', 'gitlab.om', 'gitlba.com',
    ],

    # ── Stack Overflow ──
    'stackoverflow.com': [
        'stackoverfl0w.com', 'stackoverfloww.com', 'stack-overflow.com',
        'stackoverfow.com', 'stackoferflow.com', 'stackoverflow.co',
        'stackover.com', 'stackoveflow.com', 'stackoverflow.net',
        'stackoverfllow.com', 'stackoverflow.cm', 'stackoverfow.net',
    ],

    # ── Zomato ──
    'zomato.com': [
        'z0mato.com', 'zomatto.com', 'zomato.co', 'zomat0.com', 'zoomato.com',
        'zomto.com', 'zmato.com', 'zomato.in', 'zomato.cm', 'zomatto.in',
        'zomatto.net', 'zomot.com', 'zomato.om', 'zombato.com', 'zomato.net',
    ],

    # ── Swiggy ──
    'swiggy.com': [
        'sw1ggy.com', 'swigy.com', 'swwiggy.com', 'swiiggy.com', 'sviggy.com',
        'swiggy.co', 'siwggy.com', 'swiggg.com', 'swiggy.in', 'swiggy.cm',
        'swiogy.com', 'swiggy.net', 'swiggy.om', 'swigey.com', 'swiggY.in',
    ],

    # ── IRCTC ──
    'irctc.co.in': [
        'irtc.co.in', 'irctcc.co.in', 'irctc.com', 'irctc.in', 'irctc.co',
        'irctc.net', 'irctcco.in', 'irctconline.com', 'irctc-booking.com',
        'irctcbook.com', 'irct.co.in', 'iirctc.co.in', 'irctconline.in',
        'irctcticket.com', 'irctconline.net', 'irctcreservation.com',
    ],

    # ── MakeMyTrip ──
    'makemytrip.com': [
        'makemytripp.com', 'makemy trip.com', 'make-my-trip.com', 'makemytrp.com',
        'maakemytrip.com', 'makemytrip.co', 'makemyrip.com', 'makemytrip.in',
        'makemytrip.cm', 'mak3mytrip.com', 'makemtrip.com', 'makemy-trip.com',
    ],

    # ── Airbnb ──
    'airbnb.com': [
        'airnbnb.com', 'airrbnb.com', 'airbnbb.com', 'airbnb.co', 'air-bnb.com',
        'aribnb.com', 'airbnb.cm', 'airnbb.com', 'airbbna.com', 'airbnb.om',
        'airbnd.com', 'airbnbs.com', 'airnb.com', 'airbmb.com', 'aairbnb.com',
    ],

    # ── Booking.com ──
    'booking.com': [
        'bookking.com', 'bookingg.com', 'book1ng.com', 'b00king.com',
        'booking.co', 'bookiing.com', 'bookng.com', 'bookin.com',
        'booking.cm', 'booking.om', 'bookin9.com', 'bookingcom.com',
        'bookking.net', 'bboking.com', 'bookings.net',
    ],

    # ── Uber ──
    'uber.com': [
        'ub3r.com', 'uberr.com', 'ubber.com', 'uber.co', 'ubeer.com',
        'uber.cm', 'uber.om', 'ub-er.com', 'ubers.com', 'uuber.com',
        'uber.net', 'ub3r.net', 'uberrr.com', 'uber.in', 'uber-app.com',
    ],

    # ── Canva ──
    'canva.com': [
        'canvaa.com', 'canvva.com', 'canva.co', 'canva.cm', 'canova.com',
        'canba.com', 'canvacom.com', 'canvs.com', 'c4nva.com', 'canv4.com',
        'canva.net', 'canva.om', 'caanva.com', 'canvaa.net', 'ccanva.com',
    ],

    # ── Figma ──
    'figma.com': [
        'figmaa.com', 'f1gma.com', 'figma.co', 'figmma.com', 'figma.cm',
        'fgima.com', 'figma.net', 'figma.om', 'figgma.com', 'ffigma.com',
        'figm4.com', 'figma.io', 'figmacom.com', 'fig-ma.com', 'fiqma.com',
    ],

    # ── Adobe ──
    'adobe.com': [
        'ad0be.com', 'aadobe.com', 'adoobe.com', 'adobee.com', 'adobe.co',
        'adob3.com', 'adobe.cm', 'adobe.om', 'adobbe.com', 'ad0b3.com',
        'adobee.net', 'adobe-cc.com', 'adobecc.co', 'doobe.com', 'adob.com',
    ],

    # ── Coursera ──
    'coursera.org': [
        'courserra.org', 'coursrea.org', 'coursera.com', 'cour5era.org',
        'coursera.co', 'c0ursera.org', 'courseraa.org', 'coursear.org',
        'coursera.net', 'courseera.org', 'coarsera.org', 'coursera.cm',
    ],

    # ── Udemy ──
    'udemy.com': [
        'udmy.com', 'udemmy.com', 'udemy.co', 'ud3my.com', 'udermy.com',
        'udemy.cm', 'udemy.om', 'uudemY.com', 'udemy.net', 'udemy.in',
        'udemyy.com', 'udemy.org', 'udm3y.com', 'oudemy.com', 'udmey.com',
    ],

    # ── Wikipedia ──
    'wikipedia.org': [
        'wikpedia.org', 'wikipidia.org', 'wikepedia.org', 'wikipeda.org',
        'wikipedia.com', 'wikipeida.org', 'wiikipedia.org', 'wikipedia.co',
        'wik1pedia.org', 'wikipedia.net', 'wikipedia.cm', 'wikpedia.com',
        'wikipeddia.org', 'wikkipedia.org', 'wikopedia.org', 'wikipedia.om',
    ],

    # ── ChatGPT / OpenAI ──
    'openai.com': [
        'opena1.com', 'openai.co', 'op3nai.com', 'openaii.com', 'openal.com',
        'openai.cm', 'op3nai.net', 'openai.om', 'opneai.com', 'openai.net',
        'opeani.com', 'openaicom.com', 'openai.org', 'openei.com', 'open-ai.com',
    ],
    'chatgpt.com': [
        'chatgp.com', 'chatgptt.com', 'ch4tgpt.com', 'chatgpt.co', 'chatgbt.com',
        'chatgpt.cm', 'chat-gpt.com', 'chatgpt.net', 'chatgppt.com', 'chatgpt.om',
        'chatgot.com', 'chatpt.com', 'chaatgpt.com', 'chatgpt.org', 'chatgpts.com',
    ],

    # ── PayPal India ──
    'razorpay.com': [
        'razorpay.co', 'raz0rpay.com', 'razorpayy.com', 'razorpai.com',
        'razorpay.in', 'rasorpay.com', 'razorpay.cm', 'razorpay.net',
        'razorpay.om', 'razorpaay.com', 'razorpaycom.com', 'razopray.com',
    ],

    # ── Nykaa ──
    'nykaa.com': [
        'nykaa.co', 'nyk4a.com', 'nykaaa.com', 'nyk-aa.com', 'nykaa.cm',
        'nykaa.in', 'nykkaa.com', 'nykaa.net', 'nykaas.com', 'nykaa.om',
        'nykaa.org', 'nykana.com', 'niykaa.com', 'nykaaa.in', 'nykka.com',
    ],

    # ── Meesho ──
    'meesho.com': [
        'meesh0.com', 'meesho.co', 'meeshoo.com', 'meesho.in', 'meesho.cm',
        'me3sho.com', 'meessho.com', 'meesho.net', 'meesho.om', 'meesho.org',
        'meesho.com.in', 'meeshoo.in', 'meescho.com', 'mesho.com', 'm3esho.com',
    ],

    # ── Myntra ──
    'myntra.com': [
        'myntr4.com', 'myntraa.com', 'myntra.co', 'myntra.in', 'myntra.cm',
        'myyntra.com', 'mynttra.com', 'myntra.net', 'myntra.om', 'm7ntra.com',
        'myntra.org', 'mymtra.com', 'mynntra.com', 'mintra.com', 'myntraa.in',
    ],

    # ── Geeks for Geeks ──
    'geeksforgeeks.org': [
        'geekforgeeks.org', 'geeksforgeek.org', 'geeksforgeeks.com',
        'geeksfor geeks.org', 'geeksforgeeks.co', 'geekforgeeks.com',
        'geeksforge3ks.org', 'geeksforgeeks.net', 'geeksforgeeks.cm',
        'geeksforgeeks.in', 'geeksforgeks.org', 'g3eksforgeeks.org',
    ],

    # ── LeetCode ──
    'leetcode.com': [
        'leet-code.com', 'leatcode.com', 'leetcod3.com', 'leetcode.co',
        'leetcoode.com', 'leetcode.cm', 'l3etcode.com', 'leetcode.net',
        'leetcode.om', 'leetcde.com', 'leetcodee.com', 'leetcodes.com',
        'leetc0de.com', 'leeetcode.com', 'leetcode.org',
    ],

    # ── HackerRank ──
    'hackerrank.com': [
        'hackerran.com', 'hackerrnk.com', 'hacker-rank.com', 'hackerank.com',
        'hackerrank.co', 'hackerankk.com', 'hackerrankk.com', 'hackerrank.cm',
        'hackerrank.net', 'hackerrank.om', 'hackerrank.in', 'hackrrank.com',
    ],

    # ── Cloudflare ──
    'cloudflare.com': [
        'cl0udflare.com', 'cloudffare.com', 'cloudflar.com', 'cloud-flare.com',
        'cloudflare.co', 'cloudflare.cm', 'cloudflre.com', 'cloudflare.net',
        'cloudfllare.com', 'cloudflare.om', 'c1oudflare.com', 'clodflare.com',
    ],
}

# Flat lookup: fake_domain -> real_domain
TYPOSQUAT_LOOKUP = {}
for real, fakes in TYPOSQUATS.items():
    for fake in fakes:
        TYPOSQUAT_LOOKUP[fake.lower()] = real


def is_whitelisted(domain):
    domain = domain.lower()
    return any(domain == w or domain.endswith('.' + w) for w in WHITELIST)


def is_legit_brand_domain(brand, domain):
    """Returns True if domain is a legitimate official domain for that brand."""
    suffixes = [
        f'{brand}.com', f'{brand}.in', f'{brand}.sbi',
        f'{brand}.bank.in', f'{brand}.co.in', f'{brand}.gov.in',
        f'{brand}.net', f'{brand}.org', f'{brand}.co',
        f'{brand}.io', f'{brand}.app', f'{brand}.ai',
        f'{brand}.tv', f'{brand}.us', f'{brand}.uk',
        f'{brand}.co.uk', f'{brand}.com.au',
    ]
    return any(domain.endswith(s) for s in suffixes)


def check_typosquat(domain):
    """Returns the real site if this domain is a known or fuzzy typosquat."""
    domain = domain.lower().replace('www.', '')

    # Direct lookup
    if domain in TYPOSQUAT_LOOKUP:
        return TYPOSQUAT_LOOKUP[domain]

    # Skip if already whitelisted
    if is_whitelisted(domain):
        return None

    # Fuzzy match against all legit domains
    all_legit = list(TYPOSQUATS.keys()) + [w for w in WHITELIST if '.' in w]
    close = difflib.get_close_matches(domain, all_legit, n=1, cutoff=0.88)
    if close and close[0] != domain:
        return close[0]

    return None


def calculate_score(flagged, num_reasons, url=""):
    score = 100
    if flagged:
        score -= 50
        score -= (max(num_reasons - 1, 0) * 15)
    if url:
        score -= analyze_url(url)
    return max(score, 5)


def analyze_url(url):
    penalty = 0
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        full_url = url.lower()
        path = parsed.path.lower()
        clean_domain = domain.replace('www.', '')

        # Whitelisted — no penalty
        if is_whitelisted(domain):
            return 0

        # Typosquat check
        if check_typosquat(clean_domain):
            penalty += 45

        # No HTTPS
        if parsed.scheme == 'http':
            penalty += 20

        # Raw IP address
        if re.match(r'^\d+\.\d+\.\d+\.\d+', domain):
            penalty += 35

        # Misspelled brands (leet speak)
        leet = ['amaz0n', 'g00gle', 'paypa1', 'paypai', 'micros0ft',
                'netfl1x', 'faceb00k', 'appl3', 'fl1pkart', 'flickart',
                'g1thub', 'githb', 'githubb', 'youttube', 'youtub3']
        for fake in leet:
            if fake in domain:
                penalty += 40
                break

        # Suspicious TLDs
        bad_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
                    '.click', '.download', '.loan', '.win', '.party',
                    '.buzz', '.fun', '.rest', '.gdn', '.stream']
        if any(domain.endswith(t) for t in bad_tlds):
            penalty += 25

        # Long URL
        if len(url) > 200: penalty += 25
        elif len(url) > 120: penalty += 12

        # Too many hyphens
        hyphens = domain.count('-')
        if hyphens >= 3: penalty += 25
        elif hyphens == 2: penalty += 12
        elif hyphens == 1: penalty += 5

        # Too many subdomains
        if domain.count('.') >= 4: penalty += 25
        elif domain.count('.') == 3: penalty += 10

        # Brand impersonation
        for brand in BRANDS:
            if brand in domain and not is_legit_brand_domain(brand, domain):
                penalty += 35
                break

        # Scam keywords
        scam_words = ['free-iphone', 'free-money', 'win-prize', 'winner',
                      'claim-prize', 'instant-cash', 'lottery', 'jackpot',
                      'giveaway', 'free-gift', 'cash-reward', 'free-recharge']
        found_scam = [w for w in scam_words if w in full_url]
        if len(found_scam) >= 2: penalty += 35
        elif len(found_scam) == 1: penalty += 18

        # Sensitive keywords
        sensitive = ['otp', 'cvv', 'aadhaar', 'pan-card', 'bank-detail',
                     'kyc', 'verify-account', 'ifsc', 'account-number']
        found_s = [w for w in sensitive if w in full_url]
        if len(found_s) >= 2: penalty += 30
        elif len(found_s) == 1: penalty += 10

        # Dangerous file extensions
        dangerous_ext = ['.exe', '.bat', '.cmd', '.msi', '.vbs', '.scr', '.apk', '.ps1']
        if any(path.endswith(e) for e in dangerous_ext):
            penalty += 40

        # @ symbol
        if '@' in full_url: penalty += 25

        # Heavily encoded URL
        if full_url.count('%') > 5: penalty += 20

        # Redirect patterns
        redirect_words = ['redirect', 'redir', 'goto', 'click?url=']
        if any(w in full_url for w in redirect_words):
            penalty += 20

    except Exception as e:
        print(f"analyze_url error: {e}")

    return penalty


def get_url_reasons(url):
    reasons = []
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        full_url = url.lower()
        path = parsed.path.lower()
        clean_domain = domain.replace('www.', '')

        # Typosquat check FIRST — before whitelist
        real_site = check_typosquat(clean_domain)
        if real_site:
            reasons.append(f"Possible typo — did you mean '{real_site}'?")

        # Whitelisted — no further reasons
        if is_whitelisted(domain):
            return reasons

        if parsed.scheme == 'http':
            reasons.append("No SSL encryption — uses HTTP not HTTPS")

        if re.match(r'^\d+\.\d+\.\d+\.\d+', domain):
            reasons.append("Uses raw IP address instead of domain name")

        leet = ['amaz0n', 'g00gle', 'paypa1', 'paypai', 'micros0ft',
                'netfl1x', 'faceb00k', 'appl3', 'fl1pkart', 'flickart',
                'g1thub', 'githb', 'githubb', 'youttube', 'youtub3']
        if any(f in domain for f in leet):
            reasons.append("Misspelled brand name — possible impersonation")

        bad_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
                    '.click', '.download', '.loan', '.win', '.party',
                    '.buzz', '.fun', '.rest', '.gdn', '.stream']
        if any(domain.endswith(t) for t in bad_tlds):
            reasons.append("Suspicious domain extension (commonly used in scams)")

        for brand in BRANDS:
            if brand in domain and not is_legit_brand_domain(brand, domain):
                reasons.append(f"Fake '{brand}' site — possible brand impersonation")
                break

        if domain.count('-') >= 2:
            reasons.append("Multiple hyphens in domain — common phishing pattern")

        if domain.count('.') >= 4:
            reasons.append("Too many subdomains — suspicious URL structure")

        if len(url) > 120:
            reasons.append("Unusually long URL — possible obfuscation")

        scam_words = ['winner', 'lottery', 'jackpot', 'free-iphone',
                      'claim-prize', 'instant-cash', 'free-gift', 'giveaway']
        found = [w for w in scam_words if w in full_url]
        if found:
            reasons.append(f"Scam keywords in URL: {', '.join(found)}")

        sensitive = ['otp', 'cvv', 'aadhaar', 'pan-card', 'bank-detail', 'kyc']
        found_s = [w for w in sensitive if w in full_url]
        if found_s:
            reasons.append(f"Sensitive info keywords in URL: {', '.join(found_s)}")

        dangerous_ext = ['.exe', '.bat', '.cmd', '.msi', '.vbs', '.scr', '.apk']
        if any(path.endswith(e) for e in dangerous_ext):
            reasons.append("URL points to a dangerous file download")

        if '@' in full_url:
            reasons.append("@ symbol in URL — classic phishing trick")

        redirect_words = ['redirect', 'redir', 'goto', 'click?url=']
        if any(w in full_url for w in redirect_words):
            reasons.append("URL contains a redirect — could mask true destination")

        if full_url.count('%') > 5:
            reasons.append("Heavily encoded URL — characters hidden to bypass filters")

    except Exception as e:
        print(f"get_url_reasons error: {e}")

    return reasons