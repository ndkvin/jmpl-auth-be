import Joi from "joi"

const schema = Joi.object({
  token: Joi.number()
    .min(0)
    .max(999999)
    .required(),
})

export default schema