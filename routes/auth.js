import express from 'express'

const router = express.Router();

import { register } from '../controllers/auth' 

router.get('/register', register);

module.exports = router;