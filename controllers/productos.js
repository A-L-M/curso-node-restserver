const { response } = require("express");
const { Producto } = require("../models");

//obtenerProductos - paginado - total - populate(llenar la informacion del usuario relacionado)
const obtenerProductos = async (req, res = response) => {
  const { limite = 5, desde = 0 } = req.query;
  const query = { estado: true };

  const [total, productos] = await Promise.all([
    Producto.countDocuments(query),
    Producto.find(query)
      .skip(Number(desde))
      .limit(Number(limite))
      .populate("usuario", "nombre")
      .populate("categoria", "nombre"),
  ]);

  res.json({ total, productos });
};

//obtenerProducto - populate {}
const obtenerProducto = async (req, res = response) => {
  const { id } = req.params;

  const producto = await Producto.findById(id)
    .populate("usuario", "nombre")
    .populate("categoria", "nombre");

  res.json(producto);
};

const crearProducto = async (req, res = response) => {
  const { estado, usuario, nombre, ...body } = req.body;

  const productoDB = await Producto.findOne({ nombre });

  if (productoDB) {
    return res.status(400).json({
      msg: `El producto ${productoDB.nombre} ya existe`,
    });
  }

  //Generar la data a guardar
  const data = {
    nombre: nombre.toUpperCase(),
    ...body,
    usuario: req.usuario._id,
  };

  const producto = await new Producto(data);

  //Guardar en DB
  await producto.save();

  res.status(201).json(producto);
};

//actualizarProducto
const actualizarProducto = async (req, res = response) => {
  //Para extraer parametros de segmento
  const { id } = req.params;
  const { estado, usuario, ...data } = req.body;

  if (data.nombre) {
    data.nombre = data.nombre.toUpperCase();
  }
  data.usuario = req.usuario_id;

  const producto = await Producto.findByIdAndUpdate(id, data, { new: true });

  res.json(producto);
};

//borrarProducto - estado: false
const borrarProducto = async (req, res = response) => {
  const { id } = req.params;

  //Borrado por estado
  const producto = await Producto.findByIdAndUpdate(
    id,
    { estado: false },
    { new: true }
  );

  res.json({ producto });
};

module.exports = {
  obtenerProductos,
  obtenerProducto,
  crearProducto,
  actualizarProducto,
  borrarProducto,
};
