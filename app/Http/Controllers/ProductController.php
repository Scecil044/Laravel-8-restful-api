<?php

namespace App\Http\Controllers;

use App\Models\Product;
use Illuminate\Http\Request;

class ProductController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        return Product::all();
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request)
    {
        $request->validate([
            'name'=> 'required',
            'slug'=> 'required',
            'price'=> 'required'
        ]);
        Product::Create($request->all());
    }

    /**
     * Display the specified resource.
     */
    public function show($id)
    {
        return Product::find($id);
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request, $id)
    {
        $product = Product::find($id);
        $product->update($request->all());
        return $product;
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy($id)
    {
        return Product::destroy($id);
    }
      /**
     * search a specified resource from storage.
     */
    public function search($name)
    {
        return Product::where('name', 'like', "%{$name}%")->get();
    }
}
