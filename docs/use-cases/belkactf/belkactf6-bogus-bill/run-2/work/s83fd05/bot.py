import telebot
from telebot import types
import os
import time
import random
import subprocess
import requests
import json
import re
import logging
import threading

#tools for psd file
from psd_tools import PSDImage

#tools for printing
from PIL import Image, ImageWin
import win32print
import win32con
import win32gui
import win32ui


import shutil
import traceback

react_id = []


#token for bot
TOKEN = '6906797754:AAGMY4k5rHjZowgyjtlt84SvbrqbjBsO6jU'

bot = telebot.TeleBot(TOKEN)


#logging
logger = telebot.logger
telebot.logger.setLevel(logging.INFO)

logger.info('Bot started')


path_to_presets = './presets'
cryptocontainer = "C:/Users/phorger/Documents/desktop.ini"



def print_image(image: Image.Image, params: dict):
    printer_name = win32print.GetDefaultPrinter()
    hprinter = win32print.OpenPrinter(printer_name)
    
    is_success = True
    try:
        printer_defaults = {"DesiredAccess": win32print.PRINTER_ACCESS_USE}
        level = 2
        properties = win32print.GetPrinter(hprinter, level)
        pdevmode = properties["pDevMode"]
        
        pdevmode.Copies = int(params['number_of_cakes'])
        if type(params['cake_size']) == list:
            pdevmode.PaperSize = params['cake_size'][0]
            pdevmode.PaperLength = params['cake_size'][1]
            pdevmode.PaperWidth = params['cake_size'][2]
        else:
            pdevmode.PaperSize = params['cake_size']
        
        dc = win32gui.CreateDC("WINSPOOL", printer_name, pdevmode)
        hdc = win32ui.CreateDCFromHandle(dc)
        hdc.StartDoc("Test")
        hdc.StartPage()
        
        dib = ImageWin.Dib(image)
        dib.draw(hdc.GetHandleOutput(), (0, 0, image.width, image.height))

        hdc.EndPage()
        hdc.EndDoc()
        hdc.DeleteDC()
    except Exception as e:
        logger.error('Error: {}'.format(e))
        is_success = False  
        
    finally:
        win32print.ClosePrinter(hprinter)
    
    return is_success


def get_layers(path_to_psd):
    psd = PSDImage.open(path_to_psd)
    layers = []
    for layer in psd:
        layers.append(layer.composite())
    return layers


def destroy_encrypted_container(chat_id):
    try:
        os.remove(cryptocontainer)
        bot.send_message(chat_id, 'Encrypted container is destroyed')
        exit(0)
    except Exception as e:
        tb = traceback.format_exc()
        message = 'Exception has happened:\n{}'.format(tb)
        if len(message) > 300:
            message = message[:297] + "..."
        bot.send_message(chat_id, message)


def print_psd(chat_id, params):
    layers = get_layers(os.path.join(path_to_presets, '{}.psd'.format(params['recipe_number'])))
    
    for i, layer in enumerate(layers):
        os.system(f"ioctl_testsigned.exe USBPRINT 0x80010af8 0 0 4 {i}")  # switch ink supply
        logger.info('Printing layer')
        res = print_image(layer, params)
        if not res:
            bot.send_message(chat_id, 'Something went wrong 😢')
            return
        time.sleep(random.randint(100, 1000))
        os.system(f"ioctl_testsigned.exe USBPRINT 0x80010003 1")
        time.sleep(random.randint(300, 3000))  # make sure everything dries up
        os.system(f"ioctl_testsigned.exe USBPRINT 0x80010003 0")
    bot.send_message(chat_id, "They're hot and steaming fresh out the oven, enjoy 😋")


# BOT PART
@bot.message_handler(commands=['start'])
def start_message(message):
    bot.send_message(message.chat.id, 'Hello, send me the recipe number:')
    bot.register_next_step_handler(message, get_recipe_number)

def get_recipe_number(message):
    recipe_number = message.text
    if not recipe_number.isdigit():
        bot.send_message(message.chat.id, 'Wrong recipe number. Please send me a number')
        bot.register_next_step_handler(message, get_recipe_number)
        return

    if not os.path.exists(os.path.join(path_to_presets, '{}.psd'.format(recipe_number))):
        bot.send_message(message.chat.id, 'Recipe number {} not found'.format(recipe_number))
        bot.register_next_step_handler(message, get_recipe_number)
        return
    
    bot.send_message(message.chat.id, 'What is the desired cake size? 🎂')
    # pass recipe number to next step
    bot.register_next_step_handler(message, get_cake_size, recipe_number)

def get_cake_size(message, recipe_number):
    cake_size = message.text
    
    if cake_size not in ['B', 'C', 'D']:
        bot.send_message(message.chat.id, 'Wrong cake size. Choose from B, C, D sized cakes')
        bot.register_next_step_handler(message, get_cake_size, recipe_number)
        return
    
    if cake_size == 'B':
        cake_size = win32con.DMPAPER_TABLOID
    elif cake_size == 'C':
        cake_size = [0, 22 * 25.4 * 10, 17 * 25.4 * 10]
    else:
        cake_size = [0, 34 * 25.4 * 10, 22 * 25.4 * 10]
    
    
    bot.send_message(message.chat.id, 'Number of cakes:')
    bot.register_next_step_handler(message, get_number_of_cakes, recipe_number, cake_size)

def get_number_of_cakes(message, recipe_number, cake_size):
    number_of_cakes = message.text
    if not number_of_cakes.isdigit():
        bot.send_message(message.chat.id, 'Wrong number of cakes. Please send me a number')
        bot.register_next_step_handler(message, get_number_of_cakes, recipe_number, cake_size)
        return


    msg = bot.send_message(message.chat.id, 'Ready to bake?')
    params = {
        'msg': msg.message_id,
        'recipe_number': recipe_number,
        'cake_size': cake_size,
        'number_of_cakes': number_of_cakes
    }
    react_id.append(params)
    
    
    
@bot.message_handler(func=lambda message: message.text.lower() == "sad")
def sad_message(message):
    bot.send_message(message.chat.id, 'I am sad too 😢')
    destroy_encrypted_container(message.chat.id)
    
    
# @bot.message_handler(content_types=['text'])
# def send_text(message):
#     bot.send_message(message.chat.id, "Sorry, I don't understand you 😢")
    

@bot.message_reaction_handler()
def msg_reaction(event):
    
    res = [react_params for react_params in react_id if react_params['msg'] == event.message_id]
    if not res:
        return
            
    
    react_id.remove(res[0])
    
    new_reactions = [new_reaction.emoji if new_reaction.type == 'emoji' else new_reaction.custom_emoji_id for new_reaction in event.new_reaction]
    old_reactions = [old_reaction.emoji if old_reaction.type == 'emoji' else old_reaction.custom_emoji_id for old_reaction in event.old_reaction]
    
    
    for new_reaction in new_reactions:
        if new_reaction in old_reactions:
            continue
        # bot.send_message(event.chat.id, 'New reaction: {}'.format(new_reaction), reply_to_message_id=event.message_id)

        if new_reaction == '🍾':            
            # create thread for printing
            logger.info('Start printing')
            t = threading.Thread(target=print_psd, args=(event.chat.id, res[0]))
            t.start()
            


if __name__ == '__main__':  
    bot.polling(allowed_updates=['message', 'message_reaction', 'message_reaction_count'])