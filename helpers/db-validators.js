const { Role, Usuario, Categoria, Producto } = require("../models");

const esRoleValido = async (rol = "") => {
  const existeRol = await Role.findOne({ rol });
  if (!existeRol) {
    throw new Error(`El rol ${rol} no está registrado en la base de datos`);
  }
};

const emailExiste = async (correo = "") => {
  const existeEmail = await Usuario.findOne({ correo });
  if (existeEmail) {
    throw new Error(`El correo ${correo} ya está registrado`);
  }
};

const existeUsuarioPorId = async (id = "") => {
  const existeUsuario = await Usuario.findById(id);
  if (!existeUsuario) {
    throw new Error(`El id no existe: ${id}`);
  }
};

const existeCategoria = async (id = "") => {
  const categoria = await Categoria.findById(id);
  if (!categoria) {
    throw new Error(`No existe la categoria: ${id}`);
  }
};

const existeProducto = async (id = "") => {
  const producto = await Producto.findById(id);
  if (!producto) {
    throw new Error(`No existe el producto: ${id}`);
  }
};

/**
 * Validar colecciones permitidas
 */

const coleccionesPermitidas = (coleccion = "", colecciones = []) => {
  const incluida = colecciones.includes(coleccion);
  if (!incluida) {
    throw new Error(
      `La coleccion ${coleccion} no es permitidas, colecciones permitidas: ${colecciones}`
    );
  }
  return true;
};

module.exports = {
  esRoleValido,
  emailExiste,
  existeUsuarioPorId,
  existeCategoria,
  existeProducto,
  coleccionesPermitidas,
};
