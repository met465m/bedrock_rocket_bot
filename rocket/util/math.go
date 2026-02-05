package bedrock_rocket_bot

// Distance3D вычисляет расстояние между двумя точками
func Distance3D(a, b Vector3) float64 {
	dx := a.X - b.X
	dy := a.Y - b.Y
	dz := a.Z - b.Z
	return sqrt(dx*dx + dy*dy + dz*dz)
}

// sqrt — упрощённый sqrt (можно заменить на math.Sqrt)
func sqrt(x float64) float64 {
	if x == 0 {
		return 0
	}
	z := x / 2
	for i := 0; i < 10; i++ {
		z -= (z*z - x) / (2 * z)
	}
	return z
}
