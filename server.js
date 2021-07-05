import express from 'express'
import cors from 'cors'
const morgan = require('morgan');
require('dotenv').config();

const app = express();

app.use(cors());
app.use(express.json());
app.use(morgan('dev'));

app.get('/', (req, res) => {
  res.send('You hit server endpoint');
});

const port = process.env.PORT || 8000;

app.listen(port, () => console.log(`Server running on port ${port}`));