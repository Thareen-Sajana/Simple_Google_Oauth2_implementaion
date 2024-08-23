const express = require('express');
require('dotenv').config();
const bodyParser = require('body-parser');
const routes = require('./routes/routes');
const cookieParser = require('cookie-parser');
const app = express();

const port = 3000;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.json())
app.use(cookieParser())

app.use('', routes);

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})