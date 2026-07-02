const { Client, GatewayIntentBits, Partials, EmbedBuilder, ChannelType } = require('discord.js');
require('dotenv').config();

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
    GatewayIntentBits.DirectMessages,
  ],
  partials: [Partials.Channel], // needed for DMs
});

// use clientReady to avoid the deprecation warning
client.once('clientReady', (c) => {
  console.log(`✅ Bot logged in as ${c.user.tag}`);
  console.log('🔒 DM support enabled for private URL checking');
});

client.on('messageCreate', async (message) => {
  // debug: see every message the bot receives
  console.log(
    'New message:',
    message.author?.tag,
    '| type =',
    message.channel?.type,
    '| content =',
    message.content,
  );

  if (message.author?.bot) return;

  const isDM = message.channel.type === ChannelType.DM;

  const urlRegex = /(https?:\/\/[^\s]+)/g;
  const urls = message.content.match(urlRegex);

  if (urls) {
    // If message is in a server channel: give a small reply and stop
    if (!isDM) {
      try {
        await message.reply(`I saw these URLs: ${urls.join(', ')}`);
      } catch (err) {
        console.error('Reply error in guild:', err);
      }
      return;
    }

    // In DMs: do private check flow
    console.log(`\n🔒 Private URL check from ${message.author.tag}`);

    for (const url of urls) {
      console.log(`  → ${url}`);

      try {
        await message.react('🔍');

        const checkingMsg = await message.reply({
          embeds: [
            new EmbedBuilder()
              .setTitle('🔒 Private Phishing Check')
              .setDescription(`Checking URL privately: ${url.substring(0, 100)}`)
              .setColor(0x0099ff)
              .addFields(
                { name: 'Status', value: '⏳ Analyzing...', inline: true },
                { name: 'Privacy', value: '🔒 This check is private', inline: true },
              )
              .setFooter({ text: 'Phishing Detector • Private Analysis' })
              .setTimestamp(),
          ],
        });

        await new Promise((resolve) => setTimeout(resolve, 2000));

        await checkingMsg.edit({
          embeds: [
            new EmbedBuilder()
              .setTitle('✅ Private Check Complete')
              .setDescription(`URL: ${url.substring(0, 100)}`)
              .setColor(0x00ff00)
              .addFields(
                { name: 'Status', value: '✅ Check complete (demo)', inline: true },
                { name: 'Privacy', value: '🔒 Only you can see this', inline: true },
                {
                  name: 'Note',
                  value: 'Full analysis will run via AWS Lambda in the next phase.',
                  inline: false,
                },
              )
              .setFooter({ text: 'Phishing Detector • Private Analysis' })
              .setTimestamp(),
          ],
        });

        await message.react('✅');
      } catch (error) {
        console.error('❌ Error processing URL:', error);
        try {
          await message.reply('❌ Error checking URL. Please try again.');
        } catch (err) {
          console.error('❌ Failed to send error reply:', err);
        }
      }
    }
  } else if (isDM) {
    // DM without URL -> help message
    try {
      await message.reply({
        embeds: [
          new EmbedBuilder()
            .setTitle('🔒 Private Phishing Checker')
            .setDescription('Send me any URL to check it privately.')
            .addFields(
              {
                name: 'How to use',
                value: 'Just paste a URL in this DM.\nExample: `https://suspicious-site.com`',
              },
              {
                name: 'Privacy',
                value: 'All checks are **private**. Only you see the results.',
              },
            )
            .setColor(0x5865f2),
        ],
      });
    } catch (err) {
      console.error('❌ Failed to send help embed:', err);
    }
  }
});

client.on('error', (error) => {
  console.error('❌ Discord client error:', error);
});

process.on('unhandledRejection', (error) => {
  console.error('❌ Unhandled promise rejection:', error);
});

client.login(process.env.DISCORD_TOKEN);
