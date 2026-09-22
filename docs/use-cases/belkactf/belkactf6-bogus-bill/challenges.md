# BelkaCTF #6: Bogus Bill — the challenges

Every task from [the challenge board](https://belkasoft.com/belkactf6/chall),
in board order (left to right, top to bottom), with the story panel that
preceded it, the question verbatim and the flag format as the site states it.
Two of the twenty tiles are bonus tasks that ask for a social media post
rather than an answer from the evidence; they are marked as such.

Captured 2026-09-20, after the event closed. No answers here — see
[Answers](../README.md#answers) in the series README.

| # | Challenge | Category | Points | Solved |
| --- | --- | --- | --- | --- |
| 1 | Ident | Baby | 100 | 231 |
| 2 | Namedrop | Baby | 100 | 223 |
| 3 | Conspirators | Warmup | 100 | 172 |
| 4 | Visit | Tricky | 127 | 134 |
| 5 | Username | Baby | 100 | 188 |
| 6 | April Paycheck | Warmup | 208 | 96 |
| 7 | Party | Tricky | 643 | 14 |
| 8 | Mid-Event (bonus) | Bonus | 40 | 30 |
| 9 | Crypto | Warmup | 286 | 69 |
| 10 | Luxury | Warmup | 357 | 51 |
| 11 | Vacation | Tricky | 603 | 17 |
| 12 | Illustrator | Warmup | 438 | 36 |
| 13 | Homebrew Lab | Tricky | 438 | 36 |
| 14 | Largest Batch | Warmup | 315 | 61 |
| 15 | Device | Tricky | 357 | 51 |
| 16 | Night Shift | Tricky | 579 | 19 |
| 17 | Mole | Hard | 691 | 11 |
| 18 | Financial Institution | Hard | 829 | 5 |
| 19 | Statement | Hard | 590 | 18 |
| 20 | Congratulations! (bonus) | Final | 50 | 17 |

Points are the values the dynamic scoring had settled on when the event
closed, not what a task was worth at the start. The solve counts are the
board's own.

---

## 1. Ident

*Baby · 100 points · solved 231 times · [task page](https://belkasoft.com/belkactf6/chall/ident)*

> —Another day, another lead to chase down. A fake $50 bill passed at a corner store—talk about thrilling detective work! OK, let's see what we can find out about this little digital puppet.

**What is the Apple ID used on the imaged iPhone?**

## 2. Namedrop

*Baby · 100 points · solved 223 times · [task page](https://belkasoft.com/belkactf6/chall/namedrop)*

> —So far so good. Let's continue with the basics and get to know the guy.

**What is the iPhone owner's full name?**

Format: *First name Last name*

## 3. Conspirators

*Warmup · 100 points · solved 172 times · [task page](https://belkasoft.com/belkactf6/chall/conspirators)*

> —Chief... I think I stumbled upon something interesting.
> —Don't keep me waiting, huh? What's going on?
> —Take a look here! These guys were definitely chatting about something fishy.
> —Hm… Who was our buddy chatting with about this shady business?

**Which Telegram accounts did the owner discuss shady stuff with?**

Format: *@username, @username, @username, ...*

## 4. Visit

*Tricky · 127 points · solved 134 times · [task page](https://belkasoft.com/belkactf6/chall/visit)*

> —Chief, shouldn't we check up more on this Phorger guy?
> —Right, kid, I'll send some folks his way. Hold on. Where do I even send them?
> —It won't take long, Chief.

**Where does William live?**

Format: *latitude,longitude* — the task page also accepts a pin dropped on an embedded map.

## 5. Username

*Baby · 100 points · solved 188 times · [task page](https://belkasoft.com/belkactf6/chall/username)*

> I figured I'd hold onto the good news and keep it under wraps from the Chief... for the time being, at least. Opening the image of laptop seized Phorger's house in Belkasoft X, I delved into the investigation.
> Time to start from scratch, as usual…

The task page releases the second image here: extract
`BelkaCTF_6_CASE240405_FILE2.zip` with the password `RJtWAZfsB1wMCNDebVWY`.

**What is the username of the laptop user?**

## 6. April Paycheck

*Warmup · 208 points · solved 96 times · [task page](https://belkasoft.com/belkactf6/chall/paycheck)*

> The Chief let out an irritated puff of air, slouching halfway towards me.
> —What the heck, why didn't you just tell me straight up?
> —My bad, Chief, but…
> —But what?
> —Well, now I'm positive these guys are not your average small fry street gang. Check out the figures!

**What is the amount of William's first take in April?**

## 7. Party

*Tricky · 643 points · solved 14 times · [task page](https://belkasoft.com/belkactf6/chall/party)*

> The boss looked as pleased as punch. Trying to hide his self-satisfied smirk, he took cover in the cloud of smoke from his cigar. As a token of recognition for his past merits, he was still allowed to smoke in the office.
> —Chief, I know you like the back of my hand, a stroke of genius has struck you—so spill the beans!
> The boss waved his hands, dispersing the smoke.
> —Kid, what do you do when you finally achieve something you've long been after?
> I looked at the boss perplexedly.
> —Umm... well... I'll go take a nap.
> The boss frowned slightly.
> —What's up with the younger generation, darn it. You'll go have a drink!
> —Hmm, what do you mean?
> —I mean, we'll take the recordings from the cameras and catch the whole group!
> —Genius, boss!

**Where did the gang go to celebrate their success together in March?**

Format: *latitude,longitude* — the task page also accepts a pin dropped on an embedded map.

## 8. Mid-Event — bonus task

*Bonus · 40 points · solved 30 times · [task page](https://belkasoft.com/belkactf6/chall/bonus)*

Not a forensic task. To earn **+40** extra points, post your current standing
on your LinkedIn account and submit the link as the flag. The post must carry
both hashtags **#Belkasoft** and **#BelkaCTF**, and must stay live until the
CTF's conclusion.

## 9. Crypto

*Warmup · 286 points · solved 69 times · [task page](https://belkasoft.com/belkactf6/chall/crypto)*

> Now it was my turn to smirk, and the Chief noticed it, although I tried to conceal the grin. Apparently, I didn't have enough cigar smoke. The Chief waved his hand angrily.
> —What are you grinning at? As if you didn't get extra work.
> —Yeah, Chief. Sorry, couldn't help it.
> Thanks to the Chief's idea, we found that restaurant, but... the camera footage miraculously disappeared!
> —Any ideas on what to do next?
> —Chief, my gut tells me that guy's computer isn't squeaky clean. I'll look again for some encrypted storage. The file might be drifting in an undercurrent, hidden from plain sight.

**Which file does the guy keep his encrypted container in?**

Format: full path, e.g. *C:\VeraCrypt\MyContainer.vc*

## 10. Luxury

*Warmup · 357 points · solved 51 times · [task page](https://belkasoft.com/belkactf6/chall/luxury)*

> The Chief looked pleased again. I decrypted the encrypted file, and now he chuckled while staring at the screen.
> —There you go, rookie, learn how to live. "I'll go take a nap," haha. These people know how to have fun!

**Which luxurious item did Phorger put his laundered money into?**

Format: full name incl. any codes, e.g. *Bugatti Chiron BG744*

## 11. Vacation

*Tricky · 603 points · solved 17 times · [task page](https://belkasoft.com/belkactf6/chall/vacation)*

> —Kid, hear it through the grapevine… Phorger and his girlfriend sidekick were cooking up something... seems like they're up to their 'living large' antics again. Find out where they were planning to travel.
> —Chief, is this relevant to the case, or are you suggesting I should pick up some pseudo-living skills from the crooks?
> The Chief silently gave a mysterious glint behind his glasses.

**Which concert were Phorger and his girlfriend planning to attend in May?**

Format: artist, venue, city, e.g. *Taylor Swift, Friends Arena, Stockholm*

## 12. Illustrator

*Warmup · 438 points · solved 36 times · [task page](https://belkasoft.com/belkactf6/chall/illustrator)*

> —So...—The Chief tapped his fingers thoughtfully on the table—One can't be a good printer and a good designer at the same time, huh?
> —Yeah, that's why he talked his girlfriend into the business.
> —And we still don't know her full name?
> —On it!

**What's the name of the person who designed the print template for the bills?**

Format: *First name Last name*

## 13. Homebrew Lab

*Tricky · 438 points · solved 36 times · [task page](https://belkasoft.com/belkactf6/chall/homebrew)*

> —I can't believe it,—repeated the Chief, astonished.—She agreed to design the counterfeit templates...
> —Surprising, isn't it? Well, I'm surprised by how a 20-year-old girl managed to make such a high-quality forgery,—I replied.
> —Alright, let's get back on track. Any idea where they've set up shop?

**Where is the makeshift lab where they printed the cash located?**

Format: full address, e.g. *314 S Main St, Kirksville, MO*

## 14. Largest Batch

*Warmup · 315 points · solved 61 times · [task page](https://belkasoft.com/belkactf6/chall/batch)*

> It was my turn to smirk cunningly. Indeed, Chief seemed taken aback, a rare sight.
> —How was that even possible to figure out? Geo-what? What the hell is that?
> —Chief, hold back your surprise, or you might explode too early.
> —Come on, spill it.
> —They commanded cash prints through a bot on Telegram!
> —Damn it, what kind of word salad is that?

**What is the precise moment their largest printing batch was completed?**

Provide an exact timestamp in a common format, e.g. `2023-07-17 17:07:07 UTC`

## 15. Device

*Tricky · 357 points · solved 51 times · [task page](https://belkasoft.com/belkactf6/chall/device)*

> Sitting in the lab, I pondered over our current case. It's remarkable how just one bill led to such discoveries. As I sifted through artifacts in my Belkasoft X, I suddenly realized I knew the model of the printer used to print the fake bills. Eureka! I need to inform the Chief.

**What's the printer model they used to print money?**

For example, *Canon Color imageCLASS MF656Cdw*

## 16. Night Shift

*Tricky · 579 points · solved 19 times · [task page](https://belkasoft.com/belkactf6/chall/nightshift)*

> The Chief was humming a tune—a clear sign of good mood. He didn't even light his cigar!
> —Buddy, your printer played a great game!
> —Well, well, Chief?
> —The warranty receipt was left on it. The rest is just a matter of checking the buyer.
> —William?
> —That's the thing, it wasn't him. Seems like a bigger fish!
> —Any new intel from him?
> —Not much, but it seems our Phorger went to feed his fakes into an ATM from the second to the third of April. It'd be good to find out where.

**Which ATM did Phorger test his bills on recently?**

Format: bank and street name, e.g. *Chase ATM on S Main St*

## 17. Mole

*Hard · 691 points · solved 11 times · [task page](https://belkasoft.com/belkactf6/chall/mole)*

> —Chief, their bill quality shows some real delicate work.
> —Agreed, but what's the takeaway?
> —They had insider info.
> —Hinting at technical details of the bill validator?
> I added a touch of flattery to my voice.
> — You're the man for a reason, Chief!

**Who leaked the technical data on the bill validator to the gang?**

Format: *First name Last name*

## 18. Financial Institution

*Hard · 829 points · solved 5 times · [task page](https://belkasoft.com/belkactf6/chall/financial)*

> I shuffled into the Chief's office, slumping slightly. He seemed to notice but didn't acknowledge it.
> —Bad news, Chief.
> —Lay it on me.
> —I couldn't decrypt the talks with Chase, there seems to be some unconventional encryption going on.
> —Not good. He's the right hand to the boss, he would know the ins and outs of gang's cash flow.

**Which offshore financial institution did the gang bank with?**

Provide its *SWIFT code*.

## 19. Statement

*Hard · 590 points · solved 18 times · [task page](https://belkasoft.com/belkactf6/chall/statement)*

> The Chief appeared once again gleefully excited. On his desk, I spotted the book "Follow the Money" by Paul Johnson. He bellowed at me as soon as I stepped in:
> — I know for sure we've got them all, except one!
> — But how...
> The Chief interrupted:
> — Bring me Phorger's statement, pronto!
> I didn't quite catch what he called me, but I hustled to carry out the order.

**Paste Phorger's entire bank statement here, containing all his offshore transactions**

## 20. Congratulations! — bonus task

*Final · 50 points · solved 17 times · [task page](https://belkasoft.com/belkactf6/chall/congrats)*

Not a forensic task. The closing tile: **+50** bonus points for posting about
the CTF on LinkedIn or Twitter and submitting the link as the flag, with both
hashtags **#Belkasoft** and **#BelkaCTF**, the post staying live until the
CTF's conclusion.
