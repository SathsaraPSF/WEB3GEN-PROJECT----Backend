const express = require('express');
const dotenv = require('dotenv').config();
const cors = require('cors');
const {mongoose} = require('mongoose');
const cookiParser = require('cookie-parser')

mongoose.connect(process.env.MONGO_URL)
.then(() => console.log("Database connect"))
.catch(() => console.log("Database not connected", err))

const app = express();
app.use(express.json());
app.use(cookiParser())
app.use(express.urlencoded({extended:false}));

app.use('/',require('./routes/authRoutes'))

const port = 8000;
app.listen(port, () => console.log(`Sever is running ${port}`));