import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import express from "express";
import session from "express-session";
import passport from "passport";
import { Strategy as SteamStrategy } from "passport-steam";
import cors from "cors";
import axios from "axios";
import { v4 as uuidv4 } from "uuid";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  UpdateCommand,
  QueryCommand,
  ScanCommand,
} from "@aws-sdk/lib-dynamodb";

dotenv.config();

const app = express();

app.use(express.json());

const allowedOrigins = [
  "http://cs2.team",
  "http://www.cs2.team",
  "https://cs2.team",
  "https://www.cs2.team",
  "http://localhost:5173",
];
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      } else {
        return callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
    optionsSuccessStatus: 200,
  })
);
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    saveUninitialized: false,
    resave: false,
    cookie: {
      secure: false,
      httpOnly: false,
      sameSite: "lax",
    },
  })
);
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
  done(null, user);
});
passport.deserializeUser((obj, done) => {
  done(null, obj);
});
passport.use(
  new SteamStrategy(
    {
      returnURL: `${process.env.VITE_API_URL}/api/auth/steam/return`,
      realm: `${process.env.VITE_API_URL}`,
      apiKey: process.env.STEAM_API_KEY,
    },
    async (identifier, profile, done) => {
      process.nextTick(async () => {
        profile.identifier = identifier;

        const params = {
          TableName: process.env.AWS_PLAYERS_TABLE_NAME,
          Key: {
            playerID: profile.id,
          },
        };

        try {
          const data = await dynamoDbDocClient.send(new GetCommand(params));

          if (!data.Item) {
            const playerCreatedDateTime = new Date().toISOString();

            let playerCountry = null;
            const apiKey = process.env.STEAM_API_KEY;
            const url = `http://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/?key=${apiKey}&steamids=${profile.id}`;

            try {
              const response = await axios.get(url);
              const steamProfile = response.data.response.players[0];
              if (steamProfile.loccountrycode) {
                playerCountry = steamProfile.loccountrycode;
              }
            } catch (error) {
              console.error("Error fetching user country from Steam:", error);
            }

            const newUserParams = {
              TableName: process.env.AWS_PLAYERS_TABLE_NAME,
              Item: {
                playerID: profile.id,
                playerUsername: profile.displayName,
                playerCreatedDateTime: playerCreatedDateTime,
                playerUpdatedDateTime: playerCreatedDateTime,
                playerPrivate: false,
                playerCountry: playerCountry,
                playerLanguage: "English",
              },
            };

            await dynamoDbDocClient.send(new PutCommand(newUserParams));
          }

          return done(null, profile);
        } catch (error) {
          console.error("Error accessing database:", error);
          return done(error, null);
        }
      });
    }
  )
);

const dynamoDbClient = new DynamoDBClient({
  region: process.env.AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});
const dynamoDbDocClient = DynamoDBDocumentClient.from(dynamoDbClient);

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ error: "User not authenticated" });
}

function validateTeamNameAndTag(teamName, teamTag) {
  const namePattern = /^(?!.*\s{2,})[a-zA-Z0-9\s]*$/;
  const tagPattern = /^(?!.*\s{2,})[a-zA-Z0-9\s]*$/;

  if (
    !teamName ||
    teamName.length < 3 ||
    teamName.length > 30 ||
    !namePattern.test(teamName) ||
    teamName.trim() !== teamName
  ) {
    return { valid: false, message: "Invalid team name" };
  }

  if (
    !teamTag ||
    teamTag.length < 2 ||
    teamTag.length > 5 ||
    !tagPattern.test(teamTag) ||
    teamTag.trim() !== teamTag
  ) {
    return { valid: false, message: "Invalid team tag" };
  }

  return { valid: true };
}

app.get("/healthcheck", (req, res) => {
  res.sendStatus(200);
});

app.get(
  "/api/auth/steam",
  passport.authenticate("steam", { failureRedirect: "/" }),
  (req, res) => {}
);

app.get(
  "/api/auth/steam/return",
  passport.authenticate("steam", { failureRedirect: "/" }),
  (req, res) => {
    if (req.user) {
      res.redirect(`${process.env.VITE_URL}/player/${req.user.id}`);
    } else {
      res.redirect(`${process.env.VITE_URL}`);
    }
  }
);

app.get("/api/logout", (req, res, next) => {
  if (req.isAuthenticated()) {
    req.logout((err) => {
      if (err) {
        return next(err);
      }

      req.session.destroy((err) => {
        if (err) {
          return next(err);
        }

        res.redirect(`${process.env.VITE_URL}`);
      });
    });
  } else {
    res.redirect(`${process.env.VITE_URL}`);
  }
});

app.get("/api/user", async (req, res) => {
  if (req.user) {
    const params = {
      TableName: process.env.AWS_PLAYERS_TABLE_NAME,
      Key: {
        playerID: req.user.id,
      },
    };

    try {
      const data = await dynamoDbDocClient.send(new GetCommand(params));
      const playerTeamOwner = data.Item?.playerTeamOwner || null;

      res.send({
        displayName: req.user.displayName,
        profilePicture: req.user.photos ? req.user.photos[0].value : null,
        steamid: req.user.id,
        playerTeamOwner: playerTeamOwner,
      });
    } catch (error) {
      console.error("Error fetching player data:", error);
      res.status(500).json({ error: "Error fetching player data" });
    }
  } else {
    res.send({});
  }
});

app.get("/api/player/:steamid", async (req, res) => {
  const { steamid } = req.params;
  const apiKey = process.env.STEAM_API_KEY;
  const url = `http://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/?key=${apiKey}&steamids=${steamid}`;

  try {
    const response = await axios.get(url);
    const profile = response.data.response.players[0];

    const params = {
      TableName: process.env.AWS_PLAYERS_TABLE_NAME,
      Key: {
        playerID: steamid,
      },
    };
    const data = await dynamoDbDocClient.send(new GetCommand(params));

    const {
      playerCreatedDateTime,
      playerCountry,
      playerLanguage,
      playerPrivate,
      playerDateOfBirth,
      playerGender,
      playerAbout,
      playerWebsite,
      playerX,
      playerInstagram,
      playerYouTube,
      playerTwitch,
      playerKick,
      playerTikTok,
      playerFacebook,
      playerLinkedIn,
      playerGitHub,
      playerReddit,
      playerSteam,
      playerVK,
      playerWeibo,
      playerCounterStrikeRoleEntry,
      playerCounterStrikeRoleAWPer,
      playerCounterStrikeRoleLurker,
      playerCounterStrikeRoleRifler,
      playerCounterStrikeRoleSupport,
      playerCounterStrikeRoleIGL,
      playerCounterStrikeFavouriteTeam,
      playerCounterStrikeFavouriteMap,
      playerCounterStrikeFavouriteGun,
      playerCounterStrikeFavouriteKnife,
      playerTeamOwner,
    } = data.Item || {};

    const combinedData = {
      ...profile,
      playerCreatedDateTime: playerCreatedDateTime || null,
      country: playerCountry || null,
      language: playerLanguage || null,
      dateOfBirth: playerDateOfBirth || null,
      gender: playerGender || null,
      private: playerPrivate !== undefined ? playerPrivate : null,
      about: playerAbout || null,
      lastOnline: profile.lastlogoff
        ? new Date(profile.lastlogoff * 1000)
        : null,
      website: playerWebsite || null,
      x: playerX || null,
      instagram: playerInstagram || null,
      youtube: playerYouTube || null,
      twitch: playerTwitch || null,
      kick: playerKick || null,
      tiktok: playerTikTok || null,
      facebook: playerFacebook || null,
      linkedin: playerLinkedIn || null,
      github: playerGitHub || null,
      reddit: playerReddit || null,
      steam: playerSteam || null,
      vk: playerVK || null,
      weibo: playerWeibo || null,
      playerCounterStrikeRoleEntry: playerCounterStrikeRoleEntry || false,
      playerCounterStrikeRoleAWPer: playerCounterStrikeRoleAWPer || false,
      playerCounterStrikeRoleLurker: playerCounterStrikeRoleLurker || false,
      playerCounterStrikeRoleRifler: playerCounterStrikeRoleRifler || false,
      playerCounterStrikeRoleSupport: playerCounterStrikeRoleSupport || false,
      playerCounterStrikeRoleIGL: playerCounterStrikeRoleIGL || false,
      playerCounterStrikeFavouriteTeam:
        playerCounterStrikeFavouriteTeam || null,
      playerCounterStrikeFavouriteMap: playerCounterStrikeFavouriteMap || null,
      playerCounterStrikeFavouriteGun: playerCounterStrikeFavouriteGun || null,
      playerCounterStrikeFavouriteKnife:
        playerCounterStrikeFavouriteKnife || null,
      playerTeamOwner: playerTeamOwner || null,
    };

    res.json(combinedData);
  } catch (error) {
    console.error(`Error fetching data for SteamID: ${steamid}`, error);
    res.status(500).json({ error: "Error fetching data" });
  }
});

app.get("/api/resolveVanityUrl/:vanityurl", async (req, res) => {
  const { vanityurl } = req.params;
  const apiKey = process.env.STEAM_API_KEY;
  const url = `http://api.steampowered.com/ISteamUser/ResolveVanityURL/v0001/?key=${apiKey}&vanityurl=${vanityurl}`;

  try {
    const response = await axios.get(url);
    if (response.data.response.success === 1) {
      res.json({ steamid: response.data.response.steamid });
    } else {
      res.status(404).json({ error: "Vanity URL not found" });
    }
  } catch (error) {
    res.status(500).json({ error: "Error resolving vanity URL" });
  }
});

app.get("/api/players/count", async (req, res) => {
  const params = {
    TableName: process.env.AWS_PLAYERS_TABLE_NAME,
    Select: "COUNT",
  };

  try {
    const data = await dynamoDbDocClient.send(new ScanCommand(params));
    res.json({ count: data.Count });
  } catch (error) {
    console.error("Error fetching player count:", error);
    res.status(500).json({ error: "Error fetching player count" });
  }
});

app.post("/api/createTeam", ensureAuthenticated, async (req, res) => {
  const { teamName, teamTag, steamid } = req.body;

  if (!teamName || !teamTag || !steamid) {
    console.error("Missing required fields:", { teamName, teamTag, steamid });
    return res.status(400).json({ error: "Missing required fields" });
  }

  const validation = validateTeamNameAndTag(teamName, teamTag);
  if (!validation.valid) {
    return res.status(400).json({ error: validation.message });
  }

  try {
    const playerParams = {
      TableName: process.env.AWS_PLAYERS_TABLE_NAME,
      Key: {
        playerID: steamid,
      },
    };
    const playerData = await dynamoDbDocClient.send(
      new GetCommand(playerParams)
    );

    if (playerData.Item && playerData.Item.playerTeamOwner) {
      return res.status(400).json({ error: "Player already has a team" });
    }
  } catch (error) {
    console.error("Error checking player team:", error);
    return res
      .status(500)
      .json({ error: "Error checking player team", details: error.message });
  }

  try {
    const teamNameParams = {
      TableName: process.env.AWS_TEAMS_TABLE_NAME,
      IndexName: "teamName-index",
      KeyConditionExpression: "teamName = :teamName",
      ExpressionAttributeValues: {
        ":teamName": teamName.toLowerCase(),
      },
    };

    const teamTagParams = {
      TableName: process.env.AWS_TEAMS_TABLE_NAME,
      IndexName: "teamTag-index",
      KeyConditionExpression: "teamTag = :teamTag",
      ExpressionAttributeValues: {
        ":teamTag": teamTag.toLowerCase(),
      },
    };

    const [existingTeamNames, existingTeamTags] = await Promise.all([
      dynamoDbDocClient.send(new QueryCommand(teamNameParams)),
      dynamoDbDocClient.send(new QueryCommand(teamTagParams)),
    ]);

    if (
      existingTeamNames.Items.length > 0 &&
      existingTeamTags.Items.length > 0
    ) {
      return res.status(400).json({ error: "Team name and tag already exist" });
    } else if (existingTeamNames.Items.length > 0) {
      return res.status(400).json({ error: "Team name already exists" });
    } else if (existingTeamTags.Items.length > 0) {
      return res.status(400).json({ error: "Team tag already exists" });
    }
  } catch (error) {
    console.error("Error checking existing teams:", error);
    return res
      .status(500)
      .json({ error: "Error checking existing teams", details: error.message });
  }

  const teamID = uuidv4();
  const teamCreatedDateTime = new Date().toISOString();
  const teamUpdatedDateTime = teamCreatedDateTime;
  const teamPrivate = false;
  const teamLanguage = "English";

  let teamCountry = null;
  try {
    const apiKey = process.env.STEAM_API_KEY;
    const url = `http://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/?key=${apiKey}&steamids=${steamid}`;
    const response = await axios.get(url);
    const profile = response.data.response.players[0];

    if (profile.loccountrycode) {
      teamCountry = profile.loccountrycode;
    }
  } catch (error) {
    console.error("Error fetching user country from Steam:", error);
  }

  const teamParams = {
    TableName: process.env.AWS_TEAMS_TABLE_NAME,
    Item: {
      teamID,
      teamName,
      teamTag,
      teamOwner: steamid,
      teamCreatedDateTime,
      teamUpdatedDateTime,
      teamCountry,
      teamLanguage,
      teamPrivate,
    },
  };

  const playerParamsUpdate = {
    TableName: process.env.AWS_PLAYERS_TABLE_NAME,
    Key: {
      playerID: steamid,
    },
    UpdateExpression: "set playerTeamOwner = :teamID",
    ExpressionAttributeValues: {
      ":teamID": teamID,
    },
    ReturnValues: "UPDATED_NEW",
  };

  try {
    await dynamoDbDocClient.send(new PutCommand(teamParams));
    await dynamoDbDocClient.send(new UpdateCommand(playerParamsUpdate));
    res.json({ teamID });
  } catch (error) {
    console.error("Error creating team:", error);
    res
      .status(500)
      .json({ error: "Error creating team", details: error.message });
  }
});

app.post("/api/team/:teamID/bump", ensureAuthenticated, async (req, res) => {
  const { teamID } = req.params;
  const steamid = req.user.id;

  try {
    const params = {
      TableName: process.env.AWS_TEAMS_TABLE_NAME,
      Key: {
        teamID,
      },
    };
    const data = await dynamoDbDocClient.send(new GetCommand(params));

    if (!data.Item) {
      return res.status(404).json({ error: "Team not found" });
    }

    if (data.Item.teamOwner !== steamid) {
      return res
        .status(403)
        .json({ error: "You are not the owner of this team" });
    }

    const lastUpdated = new Date(data.Item.teamUpdatedDateTime);
    const now = new Date();
    const timeDiff = now.getTime() - lastUpdated.getTime();

    if (timeDiff < 24 * 60 * 60 * 1000) {
      return res
        .status(400)
        .json({ error: "You can only bump the team once every 24 hours" });
    }

    const updateParams = {
      TableName: process.env.AWS_TEAMS_TABLE_NAME,
      Key: {
        teamID,
      },
      UpdateExpression: "set teamUpdatedDateTime = :now",
      ExpressionAttributeValues: {
        ":now": now.toISOString(),
      },
    };

    await dynamoDbDocClient.send(new UpdateCommand(updateParams));

    res.json({ success: true });
  } catch (error) {
    console.error("Error bumping team:", error);
    res.status(500).json({ error: "Error bumping team" });
  }
});

app.get("/api/team/:teamID", async (req, res) => {
  const { teamID } = req.params;
  const params = {
    TableName: process.env.AWS_TEAMS_TABLE_NAME,
    Key: {
      teamID,
    },
  };

  try {
    const data = await dynamoDbDocClient.send(new GetCommand(params));
    if (!data.Item) {
      return res.status(404).json({ error: "Team not found" });
    }

    const ownerParams = {
      TableName: process.env.AWS_PLAYERS_TABLE_NAME,
      Key: {
        playerID: data.Item.teamOwner,
      },
    };
    const ownerData = await dynamoDbDocClient.send(new GetCommand(ownerParams));
    const ownerUsername = ownerData.Item ? ownerData.Item.playerUsername : null;

    const teamDataWithOwner = {
      ...data.Item,
      ownerUsername: ownerUsername,
    };

    res.json(teamDataWithOwner);
  } catch (error) {
    console.error(`Error fetching team data for teamID: ${teamID}`, error);
    res.status(500).json({ error: "Error fetching team data" });
  }
});

app.get("/api/teams", async (req, res) => {
  const { limit, lastEvaluatedKey } = req.query;

  const params = {
    TableName: process.env.AWS_TEAMS_TABLE_NAME,
    IndexName: "TeamLanguageUpdatedIndex",
    KeyConditionExpression: "teamLanguage = :teamLanguage",
    ExpressionAttributeValues: {
      ":teamLanguage": "English",
    },
    Limit: parseInt(limit) || 20,
    ExclusiveStartKey: lastEvaluatedKey
      ? JSON.parse(lastEvaluatedKey)
      : undefined,
    ScanIndexForward: false,
  };

  try {
    const data = await dynamoDbDocClient.send(new QueryCommand(params));
    res.json({
      teams: data.Items,
      lastEvaluatedKey: data.LastEvaluatedKey || null,
    });
  } catch (error) {
    console.error("Error fetching teams:", error);
    res.status(500).json({ error: "Error fetching teams" });
  }
});

app.get("/api/teams/count", async (req, res) => {
  const params = {
    TableName: process.env.AWS_TEAMS_TABLE_NAME,
    Select: "COUNT",
  };

  try {
    const data = await dynamoDbDocClient.send(new ScanCommand(params));
    res.json({ count: data.Count });
  } catch (error) {
    console.error("Error fetching team count:", error);
    res.status(500).json({ error: "Error fetching team count" });
  }
});

const port = process.env.PORT;
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
